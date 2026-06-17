// CLASSIFICATION: PUBLIC

//! `emberd-spawn-shim` — macOS spawn shim.
//!
//! ## Why this binary exists
//!
//! The macOS fork-without-exec quirk (per project memory
//! `macos_fork_without_exec_security_framework` and Apple's TN2050)
//! forbids any path that does `fork() + setuid() + <do anything with
//! Security framework>`. `sandbox_init_with_parameters(3)` is a
//! Security-framework call (it talks to `sandboxd` over Mach IPC).
//! Running it in the post-fork pre-execve window of `Command::pre_
//! exec` deadlocks unpredictably under load.
//!
//! The macOS helper replaces that pattern with **fork+exec all the way down**:
//!
//! ```text
//!  emberd-spawn-helper-macos        kernel              emberd-spawn-shim
//!         |                            |                       |
//!         |--- posix_spawn(shim) ----->|                       |
//!         |                            |--- fork+execve(shim) ->|
//!         |                            |                       |
//!         |                            |                       |  (post-execve:
//!         |                            |                       |   FRESH process
//!         |                            |                       |   image, NO Mach
//!         |                            |                       |   IPC inherited
//!         |                            |                       |   from helper)
//!         |                            |                       |
//!         |                            |                       |  read sandbox.sb
//!         |                            |                       |  sandbox_init(...)
//!         |                            |                       |  chroot+chdir
//!         |                            |                       |  setgid+setuid
//!         |                            |                       |  execve(construct)
//!         |                            |<- fork+execve -------|
//!         |                            |                       |
//!         |                            |               (construct runs as
//!         |                            |                target_uid, in
//!         |                            |                sandboxed/chrooted
//!         |                            |                image)
//! ```
//!
//! The shim's job is the privileged setup chain between two clean
//! `exec` boundaries. After the kernel's `execve` into the shim, the
//! process has a fresh address space and a fresh Mach-IPC context, so
//! the `sandbox_init_with_parameters` call talks to a clean
//! securityd/sandboxd connection. Then the shim `execve`s into the
//! real construct, replacing itself.
//!
//! ## Inputs
//!
//! Every input is required except `--chroot-dir` and `--sandbox-profile-file`:
//!
//! ```text
//! emberd-spawn-shim
//!   --target-uid <U>
//!   --target-gid <G>
//!   [--chroot-dir <D>]
//!   [--sandbox-profile-file <F>]
//!   --binary <B>
//!   -- <argv0> [<argv1>...]
//! ```
//!
//! `sandbox-profile-file` lives on a writable tmpfs directory the
//! daemon scratch-clones per spawn (`/var/db/emberlink/scratch/<id>/
//! sandbox.sb`); keeping profile bytes OUT of the argv prevents them
//! from leaking into `/proc/<pid>/cmdline` (Linux equivalent) or
//! `ps -ww` (macOS) where any local user could read them.
//!
//! ## Exit codes
//!
//! On `execve` success, the process IS the construct — the shim's
//! exit code is the construct's exit code. On any failure (bad arg,
//! sandbox_init, chroot, setuid, execve), the shim writes a structured
//! diagnostic to stderr (which is inherited by the helper and surfaces
//! in `/var/log/emberd-spawn-helper.err`) and `_exit(127)`s.
//!
//! ## What this is NOT
//!
//! - NOT a privileged binary. The shim has the same effective uid as
//!   the spawning helper (root) only briefly, between its own exec and
//!   the setuid call. After the setuid, it runs as the target uid.
//! - NOT setuid. It's `0755 root:wheel`, NOT `4755`. The kernel
//!   confers the root identity via the helper's `posix_spawn`, not
//!   via the suid bit.
//! - NOT a daemon. It's a single-shot exec target. The helper spawns
//!   one shim per `broker_exec` call; the shim execs the construct
//!   and disappears as a distinct process image.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "macos"))]
fn main() {
    // Cross-platform workspace coherence stub. The shim has no
    // semantics on Linux — there the Linux helper bin does its own
    // `setresuid + seccomp + execve` chain inline (no shim, no Mach
    // IPC concerns). Exit code 2 = misuse.
    eprintln!(
        "emberd-spawn-shim: macOS-only — this binary is built on \
         non-macOS targets only to keep the workspace coherent."
    );
    std::process::exit(2);
}

#[cfg(target_os = "macos")]
fn main() {
    macos_impl::run();
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use clap::Parser;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    /// CLI shape for the macOS helper-to-shim boundary.
    ///
    /// `--sandbox-profile-file` is a path on a writable tmpfs that the
    /// daemon scratch-clones per spawn. Keeping profile bytes out of
    /// argv is the leak-resistance invariant.
    ///
    /// `--binary` is the absolute path to the construct binary the
    /// shim `execve`s into. The hash-pin of THIS binary happens in
    /// the helper's `verify_content_hash` step BEFORE the helper
    /// invokes the shim.
    ///
    /// The trailing `-- argv...` is the construct's argv vector,
    /// including `argv[0]`.
    #[derive(Parser, Debug)]
    #[command(
        name = "emberd-spawn-shim",
        about = "macOS spawn shim (helper → shim → construct chain)",
        long_about = None,
    )]
    struct Cli {
        /// Target uid the construct runs as. Must be in the helper's
        /// pool range; the helper validates this BEFORE spawning the
        /// shim, but we accept the value here without re-validating
        /// (no policy in the shim — it's a single-purpose primitive).
        #[arg(long)]
        target_uid: u32,

        /// Target gid the construct runs as.
        #[arg(long)]
        target_gid: u32,

        /// Optional chroot root. If present, the shim `chroot()`s
        /// here and `chdir("/")` inside. If absent, no chroot is
        /// applied.
        #[arg(long)]
        chroot_dir: Option<PathBuf>,

        /// Optional path to a file containing the SBPL sandbox
        /// profile bytes. If present, the shim reads the file and
        /// calls `sandbox_init_with_parameters(profile, 0, ...)`. If
        /// absent, no sandbox is applied. Keeping profile bytes in a
        /// tmpfile (not argv) prevents leakage via `ps -ww`.
        #[arg(long)]
        sandbox_profile_file: Option<PathBuf>,

        /// Absolute path to the construct binary to `execve`.
        #[arg(long)]
        binary: PathBuf,

        /// Construct argv (including `argv[0]`). Pass after `--`.
        #[arg(trailing_var_arg = true, num_args = 0..)]
        argv: Vec<String>,
    }

    /// Diagnostic tag for the structured error line written to stderr.
    /// The helper's stderr is inherited by the shim, so anything we
    /// write here surfaces in `/var/log/emberd-spawn-helper.err`.
    #[derive(Debug, Clone, Copy)]
    enum FailStage {
        ReadSandboxProfile,
        SandboxInit,
        Chroot,
        Chdir,
        SetGid,
        SetUid,
        BadArgv,
        Execve,
    }

    impl FailStage {
        fn tag(&self) -> &'static str {
            match self {
                FailStage::ReadSandboxProfile => "READ_SANDBOX_PROFILE",
                FailStage::SandboxInit => "SANDBOX_INIT",
                FailStage::Chroot => "CHROOT",
                FailStage::Chdir => "CHDIR",
                FailStage::SetGid => "SETGID",
                FailStage::SetUid => "SETUID",
                FailStage::BadArgv => "BAD_ARGV",
                FailStage::Execve => "EXECVE",
            }
        }
    }

    /// Write the structured diagnostic and `_exit(127)`. Stderr is
    /// line-buffered; we flush via a single `write(2)` containing a
    /// trailing newline.
    fn fail(stage: FailStage, msg: &str) -> ! {
        // Format defensively — even if `write_all` fails we still
        // _exit. The helper's stderr capture will record whatever
        // got through.
        let line = format!(
            "emberd-spawn-shim: {tag}: {msg}\n",
            tag = stage.tag(),
            msg = msg
        );
        let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
        // SAFETY: `libc::_exit` does not run destructors but neither
        // do we have any in scope worth running — we're a single-
        // purpose process about to be replaced by `execve` or
        // terminated.
        unsafe { libc::_exit(127) }
    }

    pub fn run() {
        let cli = Cli::parse();

        // Step 1 — Read sandbox profile bytes from disk (if any).
        // Performed BEFORE any privilege change so I/O errors on the
        // tmpfs surface with the original root identity (helper-side
        // diagnostics see a clean errno).
        let profile_bytes = match cli.sandbox_profile_file.as_ref() {
            None => None,
            Some(path) => match std::fs::read_to_string(path) {
                Ok(s) => Some(s),
                Err(e) => fail(
                    FailStage::ReadSandboxProfile,
                    &format!("path={} errno={}", path.display(), e),
                ),
            },
        };

        // Step 2 — Apply SBPL sandbox. Now in a clean post-execve
        // process: no parent-fork Mach IPC inheritance, no async-
        // signal-safety zone. `sandbox_init_with_parameters` is
        // documented in `sandbox(7)` and used by every Apple daemon
        // that needs an SBPL profile.
        if let Some(profile) = profile_bytes.as_deref() {
            // SAFETY: `apply_sandbox` is an unsafe wrapper over the
            // C ABI; we own the CString lifetimes inside.
            let rc = unsafe { apply_sandbox(profile) };
            if rc != 0 {
                fail(
                    FailStage::SandboxInit,
                    &format!("sandbox_init_with_parameters returned {rc}"),
                );
            }
        }

        // Step 3 — chroot if requested. The chroot must happen
        // BEFORE the setuid drop so we still have CAP-equivalent
        // privilege.
        if let Some(croot) = cli.chroot_dir.as_ref() {
            let path_c = match CString::new(croot.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(e) => fail(
                    FailStage::Chroot,
                    &format!("CString({}) failed: {e}", croot.display()),
                ),
            };
            // SAFETY: `path_c` outlives the call.
            let rc = unsafe { libc::chroot(path_c.as_ptr()) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error();
                fail(
                    FailStage::Chroot,
                    &format!("chroot({}) failed: {errno}", croot.display()),
                );
            }
            // SAFETY: `c"/"` is a 'static CStr.
            let rc = unsafe { libc::chdir(c"/".as_ptr()) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error();
                fail(FailStage::Chdir, &format!("chdir(/) failed: {errno}"));
            }
        }

        // Step 4 — Privilege drop. Group first, then user. `setuid`
        // on POSIX (as root) sets real+effective+saved together;
        // libc 0.2 doesn't expose `setresuid` for Apple but `setuid`
        // is the semantically-equivalent POSIX call.
        // SAFETY: integer-only syscall.
        let rc = unsafe { libc::setgid(cli.target_gid) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error();
            fail(
                FailStage::SetGid,
                &format!("setgid({}) failed: {errno}", cli.target_gid),
            );
        }
        // SAFETY: integer-only syscall.
        let rc = unsafe { libc::setuid(cli.target_uid) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error();
            fail(
                FailStage::SetUid,
                &format!("setuid({}) failed: {errno}", cli.target_uid),
            );
        }

        // Step 5 — Build execve argv + envp. We pass the caller's
        // current env through; the helper has already done `env_clear
        // + envs(directive.env)` on the `posix_spawn` arguments, so
        // what we inherit IS the curated set.
        if cli.argv.is_empty() {
            fail(
                FailStage::BadArgv,
                "argv vector empty; cannot execve construct",
            );
        }
        let binary_c = match CString::new(cli.binary.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(e) => fail(
                FailStage::Execve,
                &format!("binary CString({}): {e}", cli.binary.display()),
            ),
        };
        let argv_cstr: Vec<CString> = match cli
            .argv
            .iter()
            .map(|a| CString::new(a.as_bytes()))
            .collect::<Result<_, _>>()
        {
            Ok(v) => v,
            Err(e) => fail(FailStage::BadArgv, &format!("argv CString failed: {e}")),
        };
        let mut argv_ptr: Vec<*const libc::c_char> = argv_cstr.iter().map(|c| c.as_ptr()).collect();
        argv_ptr.push(std::ptr::null());

        // Collect current process env into a Vec<CString>. The
        // helper's env_clear+envs sequence on `posix_spawn` already
        // curated this set.
        let envp_strs: Vec<CString> = std::env::vars_os()
            .filter_map(|(k, v)| {
                let mut buf = Vec::with_capacity(k.len() + v.len() + 1);
                buf.extend_from_slice(k.as_bytes());
                buf.push(b'=');
                buf.extend_from_slice(v.as_bytes());
                CString::new(buf).ok()
            })
            .collect();
        let mut envp_ptr: Vec<*const libc::c_char> = envp_strs.iter().map(|c| c.as_ptr()).collect();
        envp_ptr.push(std::ptr::null());

        // Step 6 — execve into the construct. If this succeeds, the
        // shim's process image is replaced and this call never
        // returns. If it fails, we drop through and emit a diagnostic.
        // SAFETY: `binary_c`, `argv_cstr`, `envp_strs` all outlive
        // the call (their owners are still alive in the function
        // frame above us, and `execve` either replaces the image or
        // returns having touched nothing).
        let _ = unsafe { libc::execve(binary_c.as_ptr(), argv_ptr.as_ptr(), envp_ptr.as_ptr()) };
        let errno = std::io::Error::last_os_error();
        fail(
            FailStage::Execve,
            &format!("execve({}) failed: {errno}", cli.binary.display()),
        );
    }

    /// Call `sandbox_init_with_parameters(profile, 0, NULL, errbuf)`.
    /// Returns the `c_int` rc; 0 = applied, non-zero = error.
    ///
    /// SBPL is officially unsupported per `sandbox(7)` since ~2017 but is
    /// still in active use by `sandboxd`, `airportd`, `mdworker`, and every
    /// WebKit content process. This path accepts that deprecation risk to keep
    /// the macOS sandbox boundary local and deterministic.
    ///
    /// # Safety
    /// Caller is responsible for ensuring `profile` is a valid UTF-8
    /// string with no interior NULs. The function `unsafe`-ly calls
    /// into the `libsandbox.dylib` C ABI but owns its CString
    /// lifetimes locally.
    unsafe fn apply_sandbox(profile: &str) -> i32 {
        unsafe extern "C" {
            fn sandbox_init(
                profile: *const libc::c_char,
                flags: u64,
                errorbuf: *mut *mut libc::c_char,
            ) -> libc::c_int;
            fn sandbox_free_error(errorbuf: *mut libc::c_char);
        }
        let Ok(profile_c) = CString::new(profile) else {
            return -1;
        };
        let mut errbuf: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: profile_c outlives the call; errbuf is a writable
        // out-parameter pointing to a stack slot. sandbox_init writes
        // either a heap-allocated message or NULL.
        let rc = unsafe { sandbox_init(profile_c.as_ptr(), 0, &mut errbuf) };
        if !errbuf.is_null() {
            // SAFETY: errbuf was heap-allocated by sandbox_init;
            // sandbox_free_error is the matching deallocator. We
            // discard the message rather than route it back to
            // stderr because it can contain quoted SBPL — the rc
            // alone is enough for the helper's diagnostic.
            unsafe { sandbox_free_error(errbuf) };
        }
        rc
    }
}
