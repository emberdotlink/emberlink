// CLASSIFICATION: PUBLIC

//! `emberd-spawn-helper-macos` — root-privileged LaunchDaemon spawn helper.
//!
//! ## Architecture
//!
//! Single-process, single-purpose. Binds an AF_UNIX stream socket at
//! `--socket <path>` with mode `0660 root:ember-clients`. Accepts one
//! connection at a time (sequential to keep the auth surface tiny and
//! the audit log linear). For each connection:
//!
//! 1. `LOCAL_PEERCRED` → refuse-and-drop if uid != `--daemon-uid`.
//! 2. Read one frame (must be `HelperFrame::Spawn`).
//! 3. Validate `protocol_version`, `binary_path`, `chroot_dir`, env-
//!    name shape, uid-in-pool via the shared
//!    [`ember_spawn_helper::validate_directive`].
//! 4. blake3-verify the construct binary; refuse-with-`HashMismatch`
//!    on divergence.
//! 5. Verify the on-disk `emberd-spawn-shim` binary's blake3 matches
//!    `EXPECTED_SHIM_HASH` (env var rendered into the LaunchDaemon
//!    plist by `ember_daemon::install`); refuse with
//!    `RefuseReason::ShimHashMismatch` on divergence.
//! 6. Write the SBPL profile (if any) to a scratch tmpfile.
//! 7. `posix_spawn(emberd-spawn-shim, --target-uid U --target-gid G
//!    --chroot-dir D --sandbox-profile-file F --binary B -- argv...)`.
//!    The shim — running in a fresh process image, NO inherited Mach
//!    IPC — performs the actual privileged setup
//!    (`sandbox_init_with_parameters` → `chroot` → `setgid/setuid`)
//!    and `execve`s the construct.
//! 8. Wait for the child; reply `HelperFrame::Exit { code }`.
//!
//! On SIGTERM the accept loop drains for up to 5 seconds then exits.
//!
//! ## Why no `pre_exec`
//!
//! The previous Path-B drop used `Command::pre_exec({ sandbox_init +
//! chroot + setuid })`. That path is invalid on macOS because the
//! post-fork pre-execve window inherits the parent's Mach IPC ports
//! and `sandbox_init` is a Security-framework call that talks to
//! `sandboxd` over Mach IPC — deadlock-prone, fork-without-exec quirk
//! per TN2050. The helper therefore uses `posix_spawn(emberd-spawn-shim)`;
//! the shim is a fresh process image after the kernel's atomic fork+exec, with
//! clean Mach IPC state.
//!
//! A regression-guard grep in `tests/spawn_shim_e2e.rs` enforces zero
//! `pre_exec` references in THIS file.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use ember_spawn_helper::{
    DEFAULT_SHIM_PATH, HelperFrame, RefuseReason, STDERR_TAIL_CAP, STDOUT_TAIL_CAP, SpawnDirective,
    format_tail,
    hash::{VerifyError, verify_content_hash},
    peercred::peer_uid,
    read_frame, refuse, validate_directive, write_frame,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser, Debug)]
#[command(
    name = "emberd-spawn-helper-macos",
    about = "Root-privileged macOS spawn helper for emberd",
    long_about = None,
)]
struct Cli {
    /// AF_UNIX path to bind. Production:
    /// `/var/run/emberd-spawn-helper.sock`.
    #[arg(long, default_value = ember_spawn_helper::DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// The ONLY uid whose connections this helper accepts. Production:
    /// the `ember` system user's uid (per ADR 131). Any other uid is
    /// refused at `LOCAL_PEERCRED` before any frame is read.
    #[arg(long)]
    daemon_uid: u32,

    /// First uid in the spawn-helper pool. REQUIRED — there is no
    /// default. The daemon's install path renders this into the
    /// LaunchDaemon plist's `ProgramArguments` so it must match
    /// `ember_daemon::install::SPAWN_POOL_UID_BASE` on the install-
    /// time host.
    #[arg(long)]
    pool_uid_base: u32,

    /// Number of slots in the spawn-helper pool. REQUIRED — there is
    /// no default. The daemon's install path renders this into the
    /// LaunchDaemon plist's `ProgramArguments`.
    #[arg(long)]
    pool_size: u32,

    /// Absolute path to the `emberd-spawn-shim` binary. Defaults to
    /// the canonical install location.
    #[arg(long, default_value = DEFAULT_SHIM_PATH)]
    shim_path: PathBuf,

    /// Scratch directory for per-spawn tmpfiles (sandbox profile
    /// bytes). Defaults to `/var/db/emberlink/scratch`. The directory
    /// must exist; the helper writes a per-spawn subdir below it.
    #[arg(long, default_value = "/var/db/emberlink/scratch")]
    scratch_dir: PathBuf,

    /// Skip the chown to `root:ember-clients` after socket bind. ONLY
    /// for tests that run the helper as the current uid (no root).
    /// Production runs do NOT pass this flag; the LaunchDaemon plist
    /// intentionally omits it.
    #[arg(long, default_value_t = false)]
    no_socket_chown: bool,
}

/// Path inside the helper's environment where the install renders
/// the blake3 of the shipped `emberd-spawn-shim`. Set by
/// `ember_daemon::install::render_spawn_helper_plist_body`. Absence
/// in production is a misconfiguration — the helper refuses every
/// spawn with `shim_hash_mismatch`.
const SHIM_HASH_ENV: &str = "EXPECTED_SHIM_HASH";

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let listener = bind_socket(&cli.socket, cli.no_socket_chown)?;
    tracing::info!(
        socket = %cli.socket.display(),
        daemon_uid = cli.daemon_uid,
        pool_uid_base = cli.pool_uid_base,
        pool_size = cli.pool_size,
        shim_path = %cli.shim_path.display(),
        "spawn-helper listening"
    );

    // Pre-create scratch dir so the per-spawn tmpfile write succeeds
    // on first request.
    if !cli.scratch_dir.exists()
        && let Err(e) = std::fs::create_dir_all(&cli.scratch_dir)
    {
        tracing::warn!(error = %e, dir = %cli.scratch_dir.display(), "could not create scratch dir; spawns will fail");
    }

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; draining and exiting");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received; draining and exiting");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        // Process sequentially: one spawn at a time.
                        if let Err(e) = handle_connection(
                            stream,
                            cli.daemon_uid,
                            cli.pool_uid_base,
                            cli.pool_size,
                            &cli.shim_path,
                            &cli.scratch_dir,
                        ).await {
                            tracing::warn!(error = %e, "connection handler failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed; sleeping 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(&cli.socket);
    Ok(())
}

/// Bind the AF_UNIX socket. Production mode is `0660 root:ember-
/// clients` — the daemon's `ember` uid joins `ember-clients` at
/// install time and connects through the group bit. Removes a stale
/// socket inode from a previous run.
///
/// The chown to `root:ember-clients` is REQUIRED on the production
/// path — the LaunchDaemon's plist sets `GroupName=ember-clients`,
/// so the inode launchd hands the helper inherits the ember-clients
/// gid. We re-chown after bind anyway to defend against operators
/// who hand-launch the helper outside launchd.
fn bind_socket(path: &Path, skip_chown: bool) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if !skip_chown {
        chown_socket_to_root_ember_clients(path)?;
    }
    Ok(listener)
}

/// Chown the UDS to `root:ember-clients`. Resolves the group via
/// `getgrnam_r("ember-clients")`. Missing group → log warning and
/// leave socket gid unchanged (`wheel` from the LaunchDaemon plist's
/// fallback — install path probes for the group's existence and
/// refuses to install if absent, so a production daemon will not
/// reach this branch).
fn chown_socket_to_root_ember_clients(path: &Path) -> std::io::Result<()> {
    let gid = match resolve_gid("ember-clients") {
        Some(gid) => gid,
        None => {
            tracing::warn!(
                "group 'ember-clients' not found via getgrnam_r; leaving \
                 socket gid unchanged. The daemon may fail to connect (the \
                 ember user is provisioned with ember-clients as a group at \
                 install time — see ember-daemon's provision_ember_user)."
            );
            return Ok(());
        }
    };
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: c_path is a valid CString; uid=0 (root) and gid from
    // getgrnam are integers libc::chown reads by value.
    let rc = unsafe { libc::chown(c_path.as_ptr(), 0, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Per-connection state machine.
async fn handle_connection(
    mut stream: UnixStream,
    daemon_uid: u32,
    pool_uid_base: u32,
    pool_size: u32,
    shim_path: &Path,
    scratch_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1) LOCAL_PEERCRED auth.
    let peer = match peer_uid(&stream) {
        Ok(uid) => uid,
        Err(e) => {
            tracing::warn!(error = %e, "peer_uid failed; dropping connection");
            return Ok(());
        }
    };
    if peer != daemon_uid {
        tracing::warn!(
            peer_uid = peer,
            expected = daemon_uid,
            "peercred mismatch; refusing"
        );
        let _ = write_frame(
            &mut stream,
            &refuse(
                RefuseReason::PeerCredMismatch,
                Some(format!("uid={peer} expected={daemon_uid}")),
            ),
        )
        .await;
        return Ok(());
    }

    // 2) Read one frame.
    let frame = match read_frame(&mut stream).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "frame read failed");
            let _ = write_frame(
                &mut stream,
                &refuse(RefuseReason::BadFrame, Some(e.to_string())),
            )
            .await;
            return Ok(());
        }
    };

    let directive = match frame {
        HelperFrame::Spawn(d) => d,
        other => {
            tracing::warn!(?other, "first frame was not Spawn; refusing");
            let _ = write_frame(
                &mut stream,
                &refuse(
                    RefuseReason::BadFrame,
                    Some("first frame must be Spawn".to_string()),
                ),
            )
            .await;
            return Ok(());
        }
    };

    // 3) Validate via the shared gate.
    if let Err(reason) = validate_directive(&directive, pool_uid_base, pool_size) {
        tracing::warn!(reason = reason.as_str(), "directive rejected");
        let _ = write_frame(&mut stream, &refuse(reason, None)).await;
        return Ok(());
    }
    if !directive.binary_path.exists() {
        let _ = write_frame(
            &mut stream,
            &refuse(
                RefuseReason::BadBinaryPath,
                Some(format!("{} not found", directive.binary_path.display())),
            ),
        )
        .await;
        return Ok(());
    }
    if let Some(chroot) = &directive.chroot_dir
        && !chroot.is_dir()
    {
        let _ = write_frame(
            &mut stream,
            &refuse(
                RefuseReason::BadChrootDir,
                Some(format!("{} not a directory", chroot.display())),
            ),
        )
        .await;
        return Ok(());
    }

    // 4) blake3 verify the construct binary.
    if let Err(VerifyError::Mismatch(m)) =
        verify_content_hash(&directive.binary_path, &directive.content_hash_blake3)
    {
        tracing::warn!(
            path = %m.path,
            expected = %m.expected,
            actual = %m.actual,
            "construct blake3 mismatch; refusing"
        );
        let _ = write_frame(
            &mut stream,
            &HelperFrame::HashMismatch {
                expected: m.expected,
                actual: m.actual,
            },
        )
        .await;
        return Ok(());
    }

    // 5) Hash-pin the shim. The helper MUST refuse to invoke a tampered shim.
    // EXPECTED_SHIM_HASH is rendered into the LaunchDaemon plist at install
    // time; missing env var is treated as a refusal (a misconfigured deploy
    // must not silently fall through to an unverified shim).
    match verify_shim_hash(shim_path) {
        ShimVerify::Ok => {}
        ShimVerify::Mismatch { expected, actual } => {
            tracing::warn!(
                shim = %shim_path.display(),
                expected = %expected,
                actual = %actual,
                "shim blake3 mismatch; refusing"
            );
            let _ = write_frame(
                &mut stream,
                &refuse(
                    RefuseReason::ShimHashMismatch,
                    Some(format!(
                        "shim={} expected={} actual={}",
                        shim_path.display(),
                        expected,
                        actual
                    )),
                ),
            )
            .await;
            return Ok(());
        }
        ShimVerify::MissingEnv => {
            tracing::warn!("EXPECTED_SHIM_HASH env var unset; refusing all spawns");
            let _ = write_frame(
                &mut stream,
                &refuse(
                    RefuseReason::ShimHashMismatch,
                    Some(
                        "EXPECTED_SHIM_HASH env var not set on helper — \
                         daemon install path must render this; re-run \
                         `ember daemon install`"
                            .to_string(),
                    ),
                ),
            )
            .await;
            return Ok(());
        }
        ShimVerify::Io(detail) => {
            tracing::warn!(
                shim = %shim_path.display(),
                detail,
                "shim hash check IO error; refusing"
            );
            let _ = write_frame(
                &mut stream,
                &refuse(
                    RefuseReason::ShimHashMismatch,
                    Some(format!("shim io error: {detail}")),
                ),
            )
            .await;
            return Ok(());
        }
    }

    // 6) Drive the posix_spawn chain.
    let invocation_id = directive.invocation_id.clone();
    let result = spawn_through_shim(&directive, shim_path, scratch_dir).await;
    match result {
        Ok((code, stdout_tail, stderr_tail)) => {
            let _ = write_frame(
                &mut stream,
                &HelperFrame::Exit {
                    code,
                    invocation_id,
                    stdout_tail,
                    stderr_tail,
                },
            )
            .await;
        }
        Err((reason, detail)) => {
            tracing::warn!(reason = reason.as_str(), detail = %detail, "spawn chain failed");
            let _ = write_frame(&mut stream, &refuse(reason, Some(detail))).await;
        }
    }
    Ok(())
}

/// Result of the shim hash-pin check.
enum ShimVerify {
    Ok,
    Mismatch { expected: String, actual: String },
    MissingEnv,
    Io(String),
}

/// Verify the on-disk `emberd-spawn-shim` blake3 against the
/// `EXPECTED_SHIM_HASH` env var. Returns `Ok` only when the env var
/// is set AND the hash matches.
fn verify_shim_hash(shim_path: &Path) -> ShimVerify {
    let expected = match std::env::var(SHIM_HASH_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => return ShimVerify::MissingEnv,
    };
    match verify_content_hash(shim_path, &expected) {
        Ok(()) => ShimVerify::Ok,
        Err(VerifyError::Mismatch(m)) => ShimVerify::Mismatch {
            expected: m.expected,
            actual: m.actual,
        },
        Err(VerifyError::Io { path, source }) => {
            ShimVerify::Io(format!("path={path} errno={source}"))
        }
    }
}

/// Drive a `posix_spawn(emberd-spawn-shim, --target-uid ... --
/// construct argv...)` call and wait for the spawned process to
/// exit.
async fn spawn_through_shim(
    directive: &SpawnDirective,
    shim_path: &Path,
    scratch_dir: &Path,
) -> Result<(i32, String, String), (RefuseReason, String)> {
    // a) Write the sandbox profile (if any) to a per-spawn tmpfile.
    //    Keeping profile bytes out of argv → not visible in `ps -ww`.
    let spawn_id = format!(
        "spawn-{}-{}",
        std::process::id(),
        // Use SystemTime to disambiguate sequential spawns.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let spawn_dir = scratch_dir.join(&spawn_id);
    std::fs::create_dir_all(&spawn_dir).map_err(|e| {
        (
            RefuseReason::SpawnFailed,
            format!("create_dir_all({}) failed: {e}", spawn_dir.display()),
        )
    })?;

    let sandbox_file: Option<PathBuf> = match directive.sandbox_profile.as_deref() {
        None => None,
        Some(profile) => {
            let path = spawn_dir.join("sandbox.sb");
            std::fs::write(&path, profile).map_err(|e| {
                (
                    RefuseReason::SpawnFailed,
                    format!("write sandbox profile {} failed: {e}", path.display()),
                )
            })?;
            // Restrict to root only — the shim still has root when it
            // reads, after which the file is unreadable to the target
            // uid.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    (
                        RefuseReason::SpawnFailed,
                        format!("chmod sandbox profile failed: {e}"),
                    )
                },
            )?;
            Some(path)
        }
    };

    // b) Build the shim argv. The shim's CLI carries every privileged
    //    setup field; the construct argv is passed after `--`.
    let mut shim_argv: Vec<String> = vec![
        shim_path
            .to_str()
            .ok_or_else(|| (RefuseReason::SpawnFailed, "shim path non-UTF-8".to_string()))?
            .to_string(),
        "--target-uid".to_string(),
        directive.target_uid.to_string(),
        "--target-gid".to_string(),
        directive.target_gid.to_string(),
        "--binary".to_string(),
        directive
            .binary_path
            .to_str()
            .ok_or_else(|| {
                (
                    RefuseReason::BadBinaryPath,
                    "binary path non-UTF-8".to_string(),
                )
            })?
            .to_string(),
    ];
    if let Some(chroot) = &directive.chroot_dir {
        shim_argv.push("--chroot-dir".to_string());
        shim_argv.push(
            chroot
                .to_str()
                .ok_or_else(|| {
                    (
                        RefuseReason::BadChrootDir,
                        "chroot dir non-UTF-8".to_string(),
                    )
                })?
                .to_string(),
        );
    }
    if let Some(file) = sandbox_file.as_ref() {
        shim_argv.push("--sandbox-profile-file".to_string());
        shim_argv.push(file.to_string_lossy().into_owned());
    }
    shim_argv.push("--".to_string());
    // Construct argv — exact pass-through. The shim's `execve` reads
    // this verbatim.
    shim_argv.extend(directive.argv.iter().cloned());

    // c) Drive the posix_spawn. Use the libc primitive directly. The
    //    workspace's `nix = 0.29` doesn't expose `posix_spawn` (only
    //    landed on master; not in 0.29.x). Inline ~40 lines of libc::
    //    posix_spawn{,attr,_file_actions} suffices. The child's
    //    stdout/stderr are wired to pipes whose read ends come back
    //    here so the helper can carry the output back to the daemon.
    let (pid, stdout_rd, stderr_rd) = posix_spawn_libc(&shim_argv, &directive.env)?;

    // d) Drain the output pipes and waitpid the shim/construct. The
    //    shim either `execve`s the construct (success, exit code is
    //    construct's) or `_exit(127)` on setup failure (which the
    //    shim's stderr captures, now surfaced in `stderr_tail`).
    //    Draining happens on dedicated threads so a child writing more
    //    than the pipe buffer never deadlocks against our wait.
    tokio::task::spawn_blocking(move || drain_and_wait(pid, stdout_rd, stderr_rd))
        .await
        .map_err(|e| (RefuseReason::SpawnFailed, format!("wait task join: {e}")))?
}

/// Set `FD_CLOEXEC` on a raw fd so it closes at the next `execve` in a
/// child that inherits it (without disturbing the parent's own copy).
fn set_cloexec(fd: libc::c_int) -> Result<(), (RefuseReason, String)> {
    // SAFETY: F_GETFD/F_SETFD are integer-only fcntl ops on an fd we own.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err((
            RefuseReason::SpawnFailed,
            format!("fcntl(F_GETFD): {}", std::io::Error::last_os_error()),
        ));
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err((
            RefuseReason::SpawnFailed,
            format!("fcntl(F_SETFD): {}", std::io::Error::last_os_error()),
        ));
    }
    Ok(())
}

/// Call `posix_spawn(2)` with file actions for stdin/stdout/stderr
/// (null in, captured out+err) and the shim path. Returns the spawned
/// pid plus the read ends of the stdout/stderr capture pipes; the
/// caller drains them via [`drain_and_wait`].
fn posix_spawn_libc(
    argv_strings: &[String],
    env: &[(String, String)],
) -> Result<(libc::pid_t, libc::c_int, libc::c_int), (RefuseReason, String)> {
    // CStrings own the underlying bytes. We hold them in vecs that
    // outlive the posix_spawn call.
    let argv_c: Vec<std::ffi::CString> = argv_strings
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|e| (RefuseReason::SpawnFailed, format!("argv CString: {e}")))?;
    let mut argv_ptr: Vec<*mut libc::c_char> =
        argv_c.iter().map(|c| c.as_ptr() as *mut _).collect();
    argv_ptr.push(std::ptr::null_mut());

    let env_c: Vec<std::ffi::CString> = env
        .iter()
        .map(|(k, v)| std::ffi::CString::new(format!("{k}={v}").into_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|e| (RefuseReason::SpawnFailed, format!("env CString: {e}")))?;
    let mut env_ptr: Vec<*mut libc::c_char> = env_c.iter().map(|c| c.as_ptr() as *mut _).collect();
    env_ptr.push(std::ptr::null_mut());

    // SAFETY: posix_spawnattr_init writes a struct; we own it
    // (zeroed) on the stack and destroy it before returning.
    let mut attr: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::posix_spawnattr_init(&mut attr) };
    if rc != 0 {
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawnattr_init: errno={rc}"),
        ));
    }
    // POSIX_SPAWN_SETSIGMASK: install an empty sigmask in the child
    // so signals delivered to the helper don't accidentally inherit.
    // SAFETY: sigemptyset is a kernel-ABI helper; mask is stack-
    // allocated.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
    }
    let rc = unsafe { libc::posix_spawnattr_setsigmask(&mut attr, &mask) };
    if rc != 0 {
        unsafe {
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawnattr_setsigmask: errno={rc}"),
        ));
    }
    // SAFETY: attr is owned by us; setflags reads it.
    let rc = unsafe {
        libc::posix_spawnattr_setflags(&mut attr, libc::POSIX_SPAWN_SETSIGMASK as libc::c_short)
    };
    if rc != 0 {
        unsafe {
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawnattr_setflags: errno={rc}"),
        ));
    }

    // SAFETY: file_actions_init writes a struct.
    let mut file_actions: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::posix_spawn_file_actions_init(&mut file_actions) };
    if rc != 0 {
        unsafe {
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawn_file_actions_init: errno={rc}"),
        ));
    }
    // stdin → /dev/null. SAFETY: c"/dev/null" is a 'static CStr.
    let rc = unsafe {
        libc::posix_spawn_file_actions_addopen(
            &mut file_actions,
            0,
            c"/dev/null".as_ptr(),
            libc::O_RDONLY,
            0,
        )
    };
    if rc != 0 {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawn_file_actions_addopen(stdin): errno={rc}"),
        ));
    }
    // stdout/stderr → capture pipes. Without this the child's output
    // was inherited onto the helper's own fds (the LaunchDaemon log)
    // and lost to the daemon — headless brokered commands saw exit
    // codes with no output. Create one pipe per stream, dup2 the write
    // end onto the child's fd 1/2, and keep the read ends here.
    //
    // cloexec discipline: all four raw fds are FD_CLOEXEC. In the
    // posix_spawn'd child the file actions run first (dup2 write→1/2,
    // creating non-cloexec fd 1/2), then the exec closes every
    // cloexec fd — so the original pipe fds vanish in the child while
    // the dup'd 1/2 survive across the shim's later execve into the
    // construct. The parent keeps its read ends (cloexec is inert for
    // a process that never execs) and closes the write ends below so
    // the read ends observe EOF when the child's fd 1/2 close.
    let mut out_pipe = [-1 as libc::c_int; 2];
    let mut err_pipe = [-1 as libc::c_int; 2];
    // SAFETY: out_pipe is a 2-int array libc::pipe writes into; rc checked.
    if unsafe { libc::pipe(out_pipe.as_mut_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: attr + file_actions are owned and initialized above.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((RefuseReason::SpawnFailed, format!("pipe(stdout): {e}")));
    }
    // SAFETY: err_pipe is a 2-int array libc::pipe writes into; rc checked.
    if unsafe { libc::pipe(err_pipe.as_mut_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: out_pipe fds + attr/file_actions are all valid here.
        unsafe {
            libc::close(out_pipe[0]);
            libc::close(out_pipe[1]);
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((RefuseReason::SpawnFailed, format!("pipe(stderr): {e}")));
    }
    for fd in [out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]] {
        if let Err(e) = set_cloexec(fd) {
            // SAFETY: all four are valid open pipe fds; attr/file_actions owned.
            unsafe {
                libc::close(out_pipe[0]);
                libc::close(out_pipe[1]);
                libc::close(err_pipe[0]);
                libc::close(err_pipe[1]);
                libc::posix_spawn_file_actions_destroy(&mut file_actions);
                libc::posix_spawnattr_destroy(&mut attr);
            }
            return Err(e);
        }
    }
    // SAFETY: file_actions is owned; out_pipe[1]/err_pipe[1] are valid
    // write ends; 1/2 are the child's stdout/stderr fds.
    let rc = unsafe { libc::posix_spawn_file_actions_adddup2(&mut file_actions, out_pipe[1], 1) };
    if rc != 0 {
        // SAFETY: all four pipe fds + attr/file_actions are valid here.
        unsafe {
            libc::close(out_pipe[0]);
            libc::close(out_pipe[1]);
            libc::close(err_pipe[0]);
            libc::close(err_pipe[1]);
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawn_file_actions_adddup2(stdout): errno={rc}"),
        ));
    }
    // SAFETY: as above.
    let rc = unsafe { libc::posix_spawn_file_actions_adddup2(&mut file_actions, err_pipe[1], 2) };
    if rc != 0 {
        // SAFETY: all four pipe fds + attr/file_actions are valid here.
        unsafe {
            libc::close(out_pipe[0]);
            libc::close(out_pipe[1]);
            libc::close(err_pipe[0]);
            libc::close(err_pipe[1]);
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!("posix_spawn_file_actions_adddup2(stderr): errno={rc}"),
        ));
    }

    // SAFETY: posix_spawn reads attr, file_actions, argv_ptr,
    // env_ptr; we own all of them and they outlive the call.
    let mut pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut pid,
            argv_c[0].as_ptr(),
            &file_actions,
            &attr,
            argv_ptr.as_ptr(),
            env_ptr.as_ptr(),
        )
    };
    unsafe {
        libc::posix_spawn_file_actions_destroy(&mut file_actions);
        libc::posix_spawnattr_destroy(&mut attr);
    }
    if rc != 0 {
        // SAFETY: all four pipe fds are valid open fds here.
        unsafe {
            libc::close(out_pipe[0]);
            libc::close(out_pipe[1]);
            libc::close(err_pipe[0]);
            libc::close(err_pipe[1]);
        }
        return Err((
            RefuseReason::SpawnFailed,
            format!(
                "posix_spawn: errno={rc} ({})",
                std::io::Error::from_raw_os_error(rc)
            ),
        ));
    }
    // Close the parent's copy of the write ends so the read ends see
    // EOF once the child's fd 1/2 close. The read ends go back to the
    // caller for draining.
    // SAFETY: out_pipe[1]/err_pipe[1] are valid write ends we own.
    unsafe {
        libc::close(out_pipe[1]);
        libc::close(err_pipe[1]);
    }
    Ok((pid, out_pipe[0], err_pipe[0]))
}

/// Drain the child's captured stdout/stderr to EOF and reap it. The
/// two pipes are drained on dedicated threads so a child that fills a
/// pipe buffer keeps making progress instead of deadlocking against
/// our `waitpid`. Returns the exit code plus the formatted output
/// tails (last [`STDOUT_TAIL_CAP`] / [`STDERR_TAIL_CAP`] bytes).
fn drain_and_wait(
    pid: libc::pid_t,
    stdout_rd: libc::c_int,
    stderr_rd: libc::c_int,
) -> Result<(i32, String, String), (RefuseReason, String)> {
    let out_h = std::thread::spawn(move || read_tail_fd(stdout_rd, STDOUT_TAIL_CAP));
    let err_h = std::thread::spawn(move || read_tail_fd(stderr_rd, STDERR_TAIL_CAP));
    let code = waitpid(pid)?;
    let (out_bytes, out_total) = out_h.join().unwrap_or_default();
    let (err_bytes, err_total) = err_h.join().unwrap_or_default();
    Ok((
        code,
        format_tail(&out_bytes, out_total),
        format_tail(&err_bytes, err_total),
    ))
}

/// Read a raw fd to EOF, retaining only the last `cap` bytes. Returns
/// the retained tail plus the total byte count seen (so the caller can
/// render a truncation marker). Closes `fd` on exit.
fn read_tail_fd(fd: libc::c_int, cap: usize) -> (Vec<u8>, usize) {
    let mut retained: Vec<u8> = Vec::new();
    let mut total: usize = 0;
    let mut chunk = [0u8; 8192];
    loop {
        // SAFETY: chunk is a valid buffer of chunk.len() bytes; fd is
        // owned by this thread.
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

/// `waitpid(pid, &status, 0)` blocking. Converts to exit code with
/// shell-style `128 + signum` on signal death.
fn waitpid(pid: libc::pid_t) -> Result<i32, (RefuseReason, String)> {
    let mut status: libc::c_int = 0;
    // SAFETY: status is a valid out-param.
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err((
            RefuseReason::SpawnFailed,
            format!("waitpid: {}", std::io::Error::last_os_error()),
        ));
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(-1)
    }
}

/// Resolve a group name via `getgrnam_r`. Returns the gid or `None`
/// if the group is missing.
fn resolve_gid(name: &str) -> Option<libc::gid_t> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: grp is filled by getgrnam_r when it returns 0 with a
    // non-NULL result pointer.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: c_name is valid; buf is writable; grp + result are
    // out-parameters.
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
    // SAFETY: result is non-null, so the dereference is valid.
    let gid = unsafe { (*result).gr_gid };
    Some(gid)
}
