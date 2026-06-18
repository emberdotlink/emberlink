// CLASSIFICATION: PUBLIC

//! `emberd-spawn-helper-linux` — hardened-Linux helper.
//!
//! Privileged sibling daemon (systemd unit, `User=root`) that performs
//! the `setuid → chroot → seccomp → execve` chain on behalf of the
//! main unprivileged `emberd`. Installed only on hardened-Linux hosts
//! where `kernel.unprivileged_userns_clone=0` (RHEL 8 default,
//! AppArmor-hardened Ubuntu/Debian) — modern Linux uses the in-daemon
//! `clone3` path and does NOT install this helper.
//!
//! ## Wire contract
//!
//! Listens on `/var/run/emberd-spawn-helper.sock` (configurable via
//! `--socket`). Mode `0660`, owner `root:ember-clients` so only the
//! main daemon uid can connect. For each accepted connection:
//!
//! 1. `SO_PEERCRED` check — peer's uid MUST equal `--daemon-uid`.
//! 2. Read one length-prefixed JSON [`HelperFrame::Spawn`] frame.
//! 3. Validate directive (protocol_version, uid in pool, env-name
//!    shape, binary-path absolute, chroot-dir absolute) via the
//!    shared gate.
//! 4. Re-hash on-disk binary via [`hash::verify_content_hash`] — the
//!    second of the two-point blake3 verify.
//! 5. `fork()`. Parent waits for the child's pre-exec progress on a
//!    status pipe; child performs
//!    `chdir → chroot? → setresgid → setresuid → seccomp? → execve`.
//! 6. Send [`HelperFrame::Exit { code, .. }`] / `HashMismatch` /
//!    `Refused` back over the socket. The child's stdout/stderr are
//!    captured via dup2'd pipes and returned as `stdout_tail` /
//!    `stderr_tail` so headless callers see command output even with
//!    no PTY bridge.
//! 7. Close the connection. The spawned child runs detached under
//!    its new uid.
//!
//! ## Privilege posture
//!
//! systemd unit MUST set `User=root` and `NoNewPrivileges=no` —
//! setresuid requires CAP_SETUID. `CapabilityBoundingSet=CAP_SETUID
//! CAP_SETGID CAP_CHOWN CAP_SYS_CHROOT` narrows the surface to
//! exactly the syscalls this binary needs. `ProtectSystem=strict` +
//! `ReadWritePaths=/var/run` prevents the helper from writing
//! anywhere except the socket dir.
//!
//! **No setuid bit on the binary** — privilege comes from the
//! systemd unit's `User=root`, not from a kernel-evaluated suid bit.
//! ADR 155 Component 4 spells out the reasoning.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
fn main() {
    // Cross-platform workspace coherence stub. The Linux helper has
    // no semantics on macOS / BSD — there `emberd-spawn-helper-macos`
    // (LaunchDaemon path) is the equivalent. Exit code 2 = misuse.
    eprintln!(
        "emberd-spawn-helper-linux: Linux-only — this binary is built on \
         non-Linux targets only to keep the workspace coherent. On macOS \
         use the LaunchDaemon-based spawn-helper (sh.emberlink.spawn-helper)."
    );
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux_impl::main()
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use clap::Parser;
    use ember_spawn_helper::{
        HelperFrame, RefuseReason, STDERR_TAIL_CAP, STDOUT_TAIL_CAP, SpawnDirective, format_tail,
        hash::{VerifyError, verify_content_hash},
        peercred::peer_uid,
        sync_io::{read_frame as sync_read_frame, write_frame as sync_write_frame},
        validate_directive,
    };
    use std::ffi::CString;
    use std::os::fd::RawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Parser, Debug)]
    #[command(
        name = "emberd-spawn-helper-linux",
        about = "Root-privileged hardened-Linux spawn helper for emberd",
        long_about = None,
    )]
    struct Cli {
        /// AF_UNIX path to bind. Production:
        /// `/var/run/emberd-spawn-helper.sock`.
        #[arg(long, default_value = ember_spawn_helper::DEFAULT_SOCKET_PATH)]
        socket: PathBuf,

        /// The ONLY uid whose connections this helper accepts.
        /// Production: the `ember` system user's uid (per ADR 131).
        #[arg(long)]
        daemon_uid: u32,

        /// Skip the setuid/chroot/seccomp chain. ONLY for tests that
        /// run the helper as the current uid (no root). Production
        /// runs do NOT pass this flag.
        #[arg(long, default_value_t = false)]
        no_privilege_drop: bool,

        /// First uid in the spawn-helper pool. REQUIRED — there is no
        /// default. The daemon's install path renders this into the
        /// systemd unit's `ExecStart` so it must match
        /// `ember_daemon::install::SPAWN_POOL_UID_BASE` on the
        /// install-time host.
        #[arg(long)]
        pool_uid_base: u32,

        /// Number of slots in the spawn-helper pool. REQUIRED — there
        /// is no default.
        #[arg(long)]
        pool_size: u32,
    }

    pub fn main() {
        let cli = Cli::parse();

        eprintln!(
            "emberd-spawn-helper-linux: starting socket={} daemon_uid={} pool=[{}..{})",
            cli.socket.display(),
            cli.daemon_uid,
            cli.pool_uid_base,
            cli.pool_uid_base.saturating_add(cli.pool_size),
        );

        if let Err(e) = run(cli) {
            eprintln!("emberd-spawn-helper-linux: fatal: {e}");
            std::process::exit(1);
        }
    }

    fn run(cli: Cli) -> Result<(), String> {
        let shutdown = Arc::new(AtomicBool::new(false));
        install_signal_handlers(Arc::clone(&shutdown))?;

        if cli.socket.exists() {
            std::fs::remove_file(&cli.socket)
                .map_err(|e| format!("remove stale socket {}: {e}", cli.socket.display()))?;
        }
        let listener = UnixListener::bind(&cli.socket)
            .map_err(|e| format!("bind {}: {e}", cli.socket.display()))?;

        // chown root:ember-clients, chmod 0660 — ember user (daemon
        // uid) is the ONLY non-root uid that may connect.
        if !cli.no_privilege_drop {
            chown_socket_to_root_ember_clients(&cli.socket)?;
        }
        let mode = libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP;
        set_mode(&cli.socket, mode as u32)?;

        while !shutdown.load(Ordering::Relaxed) {
            let (stream, _addr) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    eprintln!("emberd-spawn-helper-linux: accept: {e}");
                    continue;
                }
            };

            if let Err(e) = handle_connection(
                stream,
                cli.daemon_uid,
                cli.no_privilege_drop,
                cli.pool_uid_base,
                cli.pool_size,
            ) {
                eprintln!("emberd-spawn-helper-linux: connection error: {e}");
            }
        }

        eprintln!("emberd-spawn-helper-linux: SIGTERM received, exiting");
        let _ = std::fs::remove_file(&cli.socket);
        Ok(())
    }

    /// SIGTERM / SIGINT → set the shutdown flag. The accept loop
    /// checks it each iteration.
    fn install_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<(), String> {
        use std::sync::OnceLock;
        static SHUTDOWN_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
        SHUTDOWN_FLAG
            .set(shutdown)
            .map_err(|_| "shutdown flag already installed".to_string())?;

        extern "C" fn handler(_signum: libc::c_int) {
            if let Some(flag) = SHUTDOWN_FLAG.get() {
                flag.store(true, Ordering::Relaxed);
            }
        }

        // SAFETY: `sigaction` writes a kernel struct; the handler is
        // `extern "C"` and async-signal-safe (atomic store on a
        // static Arc is safe).
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            // Two-step cast (fn pointer → thin raw pointer → usize)
            // silences the rustc `fn_ptr_cast_to_int` lint that
            // fires on the bare `handler as usize`. The kernel
            // struct stores the same bit pattern either way —
            // `libc::sigaction::sa_sigaction` is `usize`-typed.
            sa.sa_sigaction = handler as *const () as usize;
            sa.sa_flags = 0;
            if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction(SIGTERM): {}",
                    std::io::Error::last_os_error()
                ));
            }
            if libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction(SIGINT): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }

    fn chown_socket_to_root_ember_clients(path: &Path) -> Result<(), String> {
        let gid = match getgrnam("ember-clients") {
            Some(gid) => gid,
            None => {
                eprintln!(
                    "emberd-spawn-helper-linux: group 'ember-clients' not found \
                     — leaving socket gid unchanged. Daemon will fail to connect."
                );
                return Ok(());
            }
        };

        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| format!("path CString: {e}"))?;
        // SAFETY: c_path is a valid CString; uid=0 (root) and gid
        // from getgrnam are integers that libc::chown reads by value.
        let rc = unsafe { libc::chown(c_path.as_ptr(), 0, gid) };
        if rc != 0 {
            return Err(format!(
                "chown root:ember-clients {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| format!("path CString: {e}"))?;
        // SAFETY: c_path is a valid CString; mode is a kernel-side
        // u32.
        let rc = unsafe { libc::chmod(c_path.as_ptr(), mode as libc::mode_t) };
        if rc != 0 {
            return Err(format!(
                "chmod {:o} {}: {}",
                mode,
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn getgrnam(name: &str) -> Option<u32> {
        let c_name = CString::new(name).ok()?;
        let mut buf = vec![0 as libc::c_char; 4096];
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: getgrnam_r fills `grp` or returns non-zero.
        let rc = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: result is non-null ⇒ getgrnam_r filled it.
        let gid = unsafe { (*result).gr_gid };
        Some(gid)
    }

    /// Handle one accepted connection: peercred check → read
    /// directive → validate → spawn → respond.
    fn handle_connection(
        mut stream: UnixStream,
        expected_daemon_uid: u32,
        no_privilege_drop: bool,
        pool_uid_base: u32,
        pool_size: u32,
    ) -> Result<(), String> {
        let peer = match peer_uid(&stream) {
            Ok(uid) => uid,
            Err(e) => {
                return Err(format!("peer_uid: {e}"));
            }
        };
        if peer != expected_daemon_uid {
            eprintln!(
                "emberd-spawn-helper-linux: refusing peer uid {peer} \
                 (expected daemon uid {expected_daemon_uid})"
            );
            let resp = HelperFrame::Refused {
                reason: RefuseReason::PeerCredMismatch.as_str().to_string(),
                detail: Some(format!("uid={peer} expected={expected_daemon_uid}")),
            };
            let _ = sync_write_frame(&mut stream, &resp);
            return Ok(());
        }

        let frame = match sync_read_frame(&mut stream) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(()),
            Err(e) => {
                let resp = HelperFrame::Refused {
                    reason: RefuseReason::BadFrame.as_str().to_string(),
                    detail: Some(format!("frame read: {e}")),
                };
                let _ = sync_write_frame(&mut stream, &resp);
                return Ok(());
            }
        };

        let directive = match frame {
            HelperFrame::Spawn(d) => d,
            other => {
                let resp = HelperFrame::Refused {
                    reason: RefuseReason::BadFrame.as_str().to_string(),
                    detail: Some(format!("first frame must be Spawn, got {other:?}")),
                };
                let _ = sync_write_frame(&mut stream, &resp);
                return Ok(());
            }
        };

        if let Err(reason) = validate_directive(&directive, pool_uid_base, pool_size) {
            let resp = HelperFrame::Refused {
                reason: reason.as_str().to_string(),
                detail: None,
            };
            let _ = sync_write_frame(&mut stream, &resp);
            return Ok(());
        }
        if !directive.binary_path.exists() {
            let resp = HelperFrame::Refused {
                reason: RefuseReason::BadBinaryPath.as_str().to_string(),
                detail: Some(format!("{} not found", directive.binary_path.display())),
            };
            let _ = sync_write_frame(&mut stream, &resp);
            return Ok(());
        }
        if let Some(chroot) = &directive.chroot_dir
            && !chroot.is_dir()
        {
            let resp = HelperFrame::Refused {
                reason: RefuseReason::BadChrootDir.as_str().to_string(),
                detail: Some(format!("{} not a directory", chroot.display())),
            };
            let _ = sync_write_frame(&mut stream, &resp);
            return Ok(());
        }

        if let Err(VerifyError::Mismatch(m)) =
            verify_content_hash(&directive.binary_path, &directive.content_hash_blake3)
        {
            let resp = HelperFrame::HashMismatch {
                expected: m.expected,
                actual: m.actual,
            };
            let _ = sync_write_frame(&mut stream, &resp);
            return Ok(());
        }

        let invocation_id = directive.invocation_id.clone();
        let response = match spawn_child(&directive, no_privilege_drop) {
            Ok((code, stdout_tail, stderr_tail)) => HelperFrame::Exit {
                code,
                invocation_id,
                stdout_tail,
                stderr_tail,
            },
            Err((reason, detail)) => HelperFrame::Refused {
                reason: reason.as_str().to_string(),
                detail: Some(detail),
            },
        };

        sync_write_frame(&mut stream, &response).map_err(|e| format!("write response: {e:?}"))?;
        Ok(())
    }

    /// Fork → child performs the chain (chdir/chroot/setresgid/
    /// setresuid/seccomp/execve). Parent reads the child's pre-exec
    /// status from a pipe; on success the parent observes EOF on the
    /// pipe (close-on-exec) and waits for the child. On pre-exec
    /// failure the child writes a structured tag and `_exit(127)`s.
    fn spawn_child(
        d: &SpawnDirective,
        no_privilege_drop: bool,
    ) -> Result<(i32, String, String), (RefuseReason, String)> {
        let binary_str = d
            .binary_path
            .to_str()
            .ok_or_else(|| (RefuseReason::BadBinaryPath, "non-UTF-8 path".to_string()))?;
        let binary_c = CString::new(binary_str.as_bytes())
            .map_err(|e| (RefuseReason::BadBinaryPath, format!("binary CString: {e}")))?;
        let cwd_str = d
            .cwd
            .to_str()
            .ok_or_else(|| (RefuseReason::BadBinaryPath, "non-UTF-8 cwd".to_string()))?;
        let cwd_c = CString::new(cwd_str.as_bytes())
            .map_err(|e| (RefuseReason::BadBinaryPath, format!("cwd CString: {e}")))?;
        let chroot_c =
            match d.chroot_dir.as_ref() {
                Some(p) => {
                    let s = p.to_str().ok_or_else(|| {
                        (
                            RefuseReason::BadChrootDir,
                            "non-UTF-8 chroot path".to_string(),
                        )
                    })?;
                    Some(CString::new(s.as_bytes()).map_err(|e| {
                        (RefuseReason::BadChrootDir, format!("chroot CString: {e}"))
                    })?)
                }
                None => None,
            };

        let mut argv_strs: Vec<CString> = Vec::with_capacity(d.argv.len() + 1);
        for a in &d.argv {
            argv_strs.push(
                CString::new(a.as_bytes())
                    .map_err(|e| (RefuseReason::SpawnFailed, format!("argv CString: {e}")))?,
            );
        }
        if argv_strs.is_empty() {
            let base = d
                .binary_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "construct".to_string());
            argv_strs.push(
                CString::new(base)
                    .map_err(|e| (RefuseReason::SpawnFailed, format!("argv[0] CString: {e}")))?,
            );
        }
        let argv_ptrs: Vec<*const libc::c_char> = argv_strs
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let env_strs: Vec<CString> = d
            .env
            .iter()
            .map(|(k, v)| {
                CString::new(format!("{k}={v}"))
                    .map_err(|e| (RefuseReason::SpawnFailed, format!("env CString: {e}")))
            })
            .collect::<Result<_, _>>()?;
        let env_ptrs: Vec<*const libc::c_char> = env_strs
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let mut pipefd: [libc::c_int; 2] = [-1, -1];
        // SAFETY: pipefd is a stack array sized 2 ints, libc::pipe
        // writes into it; we check rc.
        let rc = unsafe { libc::pipe(pipefd.as_mut_ptr()) };
        if rc != 0 {
            return Err((
                RefuseReason::SpawnFailed,
                format!("pipe: {}", std::io::Error::last_os_error()),
            ));
        }
        let read_fd = pipefd[0];
        let write_fd = pipefd[1];

        set_cloexec(write_fd).map_err(|e| (RefuseReason::SpawnFailed, e))?;

        // stdout/stderr capture pipes. Previously the child's output
        // was inherited onto the helper's own fds and never reached the
        // daemon — headless brokered commands saw an exit code with no
        // output. The child dup2's the write ends onto fd 1/2 and
        // closes the originals (below); the parent drains the read ends
        // and returns the tails in the `Exit` reply. No cloexec needed:
        // these are managed by hand across this explicit fork (the
        // child closes its copies; the parent never execs).
        let mut out_pipe: [libc::c_int; 2] = [-1, -1];
        let mut err_pipe: [libc::c_int; 2] = [-1, -1];
        // SAFETY: out_pipe is a 2-int array libc::pipe writes into; rc checked.
        if unsafe { libc::pipe(out_pipe.as_mut_ptr()) } != 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: read_fd/write_fd are valid open fds from the status pipe.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err((RefuseReason::SpawnFailed, format!("pipe(stdout): {e}")));
        }
        // SAFETY: err_pipe is a 2-int array libc::pipe writes into; rc checked.
        if unsafe { libc::pipe(err_pipe.as_mut_ptr()) } != 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: all four are valid open fds here.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
                libc::close(out_pipe[0]);
                libc::close(out_pipe[1]);
            }
            return Err((RefuseReason::SpawnFailed, format!("pipe(stderr): {e}")));
        }
        let out_rd = out_pipe[0];
        let out_wr = out_pipe[1];
        let err_rd = err_pipe[0];
        let err_wr = err_pipe[1];

        // SAFETY: libc::fork is fork(2); after fork the parent and
        // child diverge below. No malloc in child before execve.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            // SAFETY: the status pipe + both capture pipes are valid
            // open fds we just got from pipe(2).
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
                libc::close(out_rd);
                libc::close(out_wr);
                libc::close(err_rd);
                libc::close(err_wr);
            }
            return Err((
                RefuseReason::SpawnFailed,
                format!("fork: {}", std::io::Error::last_os_error()),
            ));
        }

        if pid == 0 {
            // ============ CHILD ==============
            // Async-signal-safe-only zone until execve. NO ALLOCATION.
            // SAFETY: read_fd + the capture read ends are unused in the
            // child; the capture write ends are dup2'd onto fd 1/2 and
            // their originals closed. dup2/close are async-signal-safe.
            unsafe {
                libc::close(read_fd);
                libc::close(out_rd);
                libc::close(err_rd);
                libc::dup2(out_wr, 1);
                libc::dup2(err_wr, 2);
                libc::close(out_wr);
                libc::close(err_wr);
            }

            // SAFETY: cwd_c is a valid CString that outlives the call.
            let rc = unsafe { libc::chdir(cwd_c.as_ptr()) };
            if rc != 0 {
                child_emit_error_and_exit(write_fd, b"CHDIR", io_errno());
            }

            if let Some(chr) = &chroot_c {
                // SAFETY: chr outlives the call.
                let rc = unsafe { libc::chroot(chr.as_ptr()) };
                if rc != 0 {
                    child_emit_error_and_exit(write_fd, b"CHROOT", io_errno());
                }
                let slash = c"/";
                // SAFETY: slash is a 'static CStr.
                unsafe {
                    libc::chdir(slash.as_ptr());
                }
            }

            if !no_privilege_drop {
                // SAFETY: integer-only syscall.
                let rc = unsafe { libc::setresgid(d.target_gid, d.target_gid, d.target_gid) };
                if rc != 0 {
                    child_emit_error_and_exit(write_fd, b"SETRESGID", io_errno());
                }
                // SAFETY: integer-only syscall.
                let rc = unsafe { libc::setresuid(d.target_uid, d.target_uid, d.target_uid) };
                if rc != 0 {
                    child_emit_error_and_exit(write_fd, b"SETRESUID", io_errno());
                }
            }

            if let Some(filter) = &d.seccomp_filter
                && !filter.is_empty()
                && let Err(errno) = install_seccomp_in_child(filter)
            {
                child_emit_error_and_exit(write_fd, b"SECCOMP", errno);
            }

            // execve. On success this never returns.
            // SAFETY: binary_c, argv_ptrs, env_ptrs all outlive the
            // call.
            let _ = unsafe {
                libc::execve(
                    binary_c.as_ptr(),
                    argv_ptrs.as_ptr() as *const *const libc::c_char,
                    env_ptrs.as_ptr() as *const *const libc::c_char,
                )
            };
            child_emit_error_and_exit(write_fd, b"EXECVE", io_errno());
        }

        // ============ PARENT ==============
        // SAFETY: write_fd + the capture write ends are unused in the
        // parent; closing them lets the capture read ends observe EOF
        // once the child's fd 1/2 close.
        unsafe {
            libc::close(write_fd);
            libc::close(out_wr);
            libc::close(err_wr);
        }

        // Drain captured stdout/stderr on dedicated threads so a chatty
        // child that fills a pipe buffer keeps making progress instead
        // of deadlocking against our status read + waitpid.
        let out_h = std::thread::spawn(move || read_tail_fd(out_rd, STDOUT_TAIL_CAP));
        let err_h = std::thread::spawn(move || read_tail_fd(err_rd, STDERR_TAIL_CAP));

        let mut buf = [0u8; 64];
        let n_read = read_all(read_fd, &mut buf);
        // SAFETY: read_fd is open and owned by us until this close.
        unsafe {
            libc::close(read_fd);
        }

        if n_read == 0 {
            // Happy path — execve succeeded. waitpid for exit code.
            let mut status: libc::c_int = 0;
            // SAFETY: status is a valid out-param for waitpid.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc < 0 {
                let _ = out_h.join();
                let _ = err_h.join();
                return Err((
                    RefuseReason::SpawnFailed,
                    format!("waitpid: {}", std::io::Error::last_os_error()),
                ));
            }
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                -1
            };
            let (out_bytes, out_total) = out_h.join().unwrap_or_default();
            let (err_bytes, err_total) = err_h.join().unwrap_or_default();
            return Ok((
                exit_code,
                format_tail(&out_bytes, out_total),
                format_tail(&err_bytes, err_total),
            ));
        }

        // Pre-exec failure path. Parse "TAG:errno\n" and reap the
        // child. Join the drain threads so their fds close (the child
        // never reached execve, so there is no useful output).
        let mut status: libc::c_int = 0;
        // SAFETY: status is a valid out-param for waitpid.
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        let _ = out_h.join();
        let _ = err_h.join();

        let payload = &buf[..n_read];
        let (tag, errno) = parse_child_error(payload);
        Err(map_child_error(&tag, errno, &d.binary_path))
    }

    /// Read a raw fd to EOF, retaining only the last `cap` bytes.
    /// Returns the retained tail plus the total byte count seen (so the
    /// caller can render a truncation marker via [`format_tail`]).
    /// Closes `fd` on exit. Runs on a dedicated drain thread.
    fn read_tail_fd(fd: RawFd, cap: usize) -> (Vec<u8>, usize) {
        let mut retained: Vec<u8> = Vec::new();
        let mut total: usize = 0;
        let mut chunk = [0u8; 8192];
        loop {
            // SAFETY: chunk is a valid buffer of chunk.len() bytes; fd
            // is owned by this thread.
            let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
            if n > 0 {
                let n = n as usize;
                total += n;
                retained.extend_from_slice(&chunk[..n]);
                if retained.len() > cap {
                    let excess = retained.len() - cap;
                    retained.drain(..excess);
                }
            } else if n == 0 {
                break; // EOF — child closed its write end.
            } else {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
        }
        // SAFETY: fd is owned by this thread and not used after close.
        unsafe {
            libc::close(fd);
        }
        (retained, total)
    }

    fn set_cloexec(fd: RawFd) -> Result<(), String> {
        // SAFETY: fcntl on an owned fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            return Err(format!(
                "fcntl(F_GETFD): {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fcntl on an owned fd.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if rc == -1 {
            return Err(format!(
                "fcntl(F_SETFD): {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn read_all(fd: RawFd, buf: &mut [u8]) -> usize {
        let mut total = 0;
        while total < buf.len() {
            // SAFETY: fd is a valid fd; buf is exclusively borrowed.
            let n = unsafe {
                libc::read(
                    fd,
                    buf.as_mut_ptr().add(total) as *mut libc::c_void,
                    buf.len() - total,
                )
            };
            if n <= 0 {
                break;
            }
            total += n as usize;
        }
        total
    }

    /// Child-side: write `TAG:errno\n` to `write_fd`, then
    /// `_exit(127)`. Async-signal-safe — uses `libc::write` directly
    /// with stack-built bytes, no allocation.
    fn child_emit_error_and_exit(write_fd: RawFd, tag: &[u8], errno: i32) -> ! {
        let mut buf = [0u8; 64];
        let mut pos = 0;
        for &b in tag {
            if pos < buf.len() {
                buf[pos] = b;
                pos += 1;
            }
        }
        if pos < buf.len() {
            buf[pos] = b':';
            pos += 1;
        }
        let mut n = errno;
        let mut digits = [0u8; 11];
        let mut dp = digits.len();
        let neg = n < 0;
        if neg {
            n = -n;
        }
        if n == 0 {
            dp -= 1;
            digits[dp] = b'0';
        } else {
            while n > 0 && dp > 0 {
                dp -= 1;
                digits[dp] = b'0' + ((n % 10) as u8);
                n /= 10;
            }
        }
        if neg && pos < buf.len() {
            buf[pos] = b'-';
            pos += 1;
        }
        while dp < digits.len() && pos < buf.len() {
            buf[pos] = digits[dp];
            dp += 1;
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b'\n';
            pos += 1;
        }
        // SAFETY: write_fd is a valid open fd; buf is stack-resident.
        unsafe {
            libc::write(write_fd, buf.as_ptr() as *const libc::c_void, pos);
            libc::_exit(127);
        }
    }

    fn io_errno() -> i32 {
        // SAFETY: __errno_location is a per-thread global accessor.
        unsafe { *libc::__errno_location() }
    }

    fn parse_child_error(buf: &[u8]) -> (String, i32) {
        let s = String::from_utf8_lossy(buf);
        let trimmed = s.trim();
        let mut parts = trimmed.splitn(2, ':');
        let tag = parts.next().unwrap_or("UNKNOWN").to_string();
        let errno: i32 = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
        (tag, errno)
    }

    fn map_child_error(tag: &str, errno: i32, binary_path: &Path) -> (RefuseReason, String) {
        let bp = binary_path.display();
        match tag {
            "CHROOT" => (
                RefuseReason::BadChrootDir,
                format!("chroot errno={errno} binary={bp}"),
            ),
            "SETRESGID" | "SETRESUID" => (
                RefuseReason::PrivilegeDropFailed,
                format!("{tag} errno={errno} binary={bp}"),
            ),
            "EXECVE" => (
                RefuseReason::SpawnFailed,
                format!("execve errno={errno} binary={bp}"),
            ),
            "SECCOMP" => (
                RefuseReason::SeccompInstallFailed,
                format!("seccomp errno={errno}"),
            ),
            "CHDIR" => (RefuseReason::SpawnFailed, format!("chdir errno={errno}")),
            other => (
                RefuseReason::SpawnFailed,
                format!("child error tag={other} errno={errno}"),
            ),
        }
    }

    /// Install a raw seccomp-bpf filter in the child. The filter
    /// bytes are the wire-encoded `sock_filter` array (8 bytes per
    /// instruction). The daemon owns the compilation; the helper is
    /// a pure carrier.
    fn install_seccomp_in_child(filter: &[u8]) -> Result<(), i32> {
        if filter.is_empty() || !filter.len().is_multiple_of(8) {
            return Err(libc::EINVAL);
        }
        let count = (filter.len() / 8) as u16;
        let fprog = libc::sock_fprog {
            len: count,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS and PR_SET_SECCOMP
        // are documented kernel APIs; arguments are integers.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
        if rc != 0 {
            return Err(io_errno());
        }
        // SAFETY: same.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &fprog as *const _ as libc::c_ulong,
                0u64,
                0u64,
            )
        };
        if rc != 0 {
            return Err(io_errno());
        }
        Ok(())
    }
}
