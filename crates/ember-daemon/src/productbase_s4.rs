use ember_authority::{
    control::AuthorityControl,
    diagnostic_bootstrap::validate_existing_state_root,
    identity,
    ipc::{
        CONTROL_FRAME_LIMIT, ControlRequest, ControlResponse, SessionActionRequest,
        SessionActionResponse, read_control_frame, read_frame, write_control_frame, write_frame,
    },
    kernel::AuthorityKernel,
    model::Refusal,
    receipt::ReceiptProjection,
    runtime_presence::ExecutionBindingAuthority,
    session_supervisor::SessionSupervisor,
};
use std::{
    fs::{self, File, OpenOptions},
    os::fd::AsRawFd as _,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

fn install_shutdown_handlers() -> Result<(), String> {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_shutdown as *const () as usize;
    action.sa_flags = 0;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
        {
            return Err(format!(
                "signal handler unavailable: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub fn run(state_root: &Path) -> Result<(), String> {
    validate_existing_state_root(state_root).map_err(|error| error.to_string())?;
    let socket_path = state_root.join("control.sock");
    let mut lease =
        DaemonLease::acquire(state_root, &socket_path).map_err(|error| error.to_string())?;
    let control = AuthorityControl::restore(state_root).map_err(|error| error.to_string())?;
    verify_daemon_executable(&control).map_err(|error| error.to_string())?;
    let listener = UnixListener::bind(&socket_path).map_err(|error| error.to_string())?;
    lease
        .claim_socket(&socket_path)
        .map_err(|error| error.to_string())?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    install_shutdown_handlers()?;
    println!(
        "emberd ProductBase authority ready: {}",
        socket_path.display()
    );
    let quiesced = AtomicBool::new(false);
    loop {
        let mut event = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut event, 1, 1_000) };
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            break;
        }
        if ready < 0 {
            eprintln!("emberd: poll failed: {}", std::io::Error::last_os_error());
            continue;
        }
        if ready == 0 {
            continue;
        }
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("emberd: accept failed: {error}");
                continue;
            }
        };
        let response = match handle_control(&control, state_root, &lease, &quiesced, &mut stream) {
            Ok(response) => response,
            Err(error) => {
                if is_durability_failure(error.code) {
                    quiesced.store(true, Ordering::SeqCst);
                }
                ControlResponse::Refusal {
                    code: error.code.into(),
                }
            }
        };
        if let Err(error) = write_control_frame(&mut stream, &response) {
            eprintln!("emberd: response failed: {error}");
        }
        if quiesced.load(Ordering::SeqCst) || SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            break;
        }
    }
    Ok(())
}

fn verify_daemon_executable(control: &AuthorityControl) -> Result<(), Refusal> {
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let digest = identity::executable_digest(&executable)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let state = control.store().snapshot()?;
    if digest != state.daemon_executable_digest {
        return Err(Refusal::new("untrusted_daemon"));
    }
    if let Some(expected_identity) = state.daemon_executable_identity {
        let pid = std::process::id();
        let pid_version = identity::process_pid_version(pid)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        let loaded_identity = identity::process_executable_identity(pid, pid_version)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        if loaded_identity != expected_identity {
            return Err(Refusal::new("untrusted_daemon"));
        }
    }
    Ok(())
}

fn handle_control(
    control: &AuthorityControl,
    state_root: &Path,
    lease: &DaemonLease,
    quiesced: &AtomicBool,
    stream: &mut UnixStream,
) -> Result<ControlResponse, Refusal> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Refusal::new("transport_failed"))?;
    let request: ControlRequest = read_control_frame(stream)?;
    let peer = ExecutionBindingAuthority::authenticate_fd(stream)?;
    lease.verify_root_identity()?;
    verify_daemon_executable(control)?;
    let state = control.verify_persisted_state(state_root)?;
    if peer.uid != state.operator_uid {
        return Err(Refusal::new("persona_mismatch"));
    }
    identity::observed_process(peer.pid, peer.pid_version)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let observed_cli = identity::process_executable_path(peer.pid, peer.pid_version)
        .and_then(fs::canonicalize)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let reviewed_cli = fs::canonicalize(cli_binary()?)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    if observed_cli != reviewed_cli {
        return Err(Refusal::new("untrusted_launcher"));
    }
    let reviewed_digest = identity::executable_digest(&reviewed_cli)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let observed_identity = identity::process_executable_identity(peer.pid, peer.pid_version)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    if reviewed_digest != state.caller_eligibility.executable_digest
        || observed_identity != state.caller_eligibility.executable_identity
    {
        return Err(Refusal::new("untrusted_launcher"));
    }
    match request {
        ControlRequest::Ping => Ok(ControlResponse::Pong),
        ControlRequest::Status => Ok(ControlResponse::Status {
            status: Box::new(AuthorityControl::read_status(&state)?),
        }),
        ControlRequest::OpenDiagnostic {
            challenge,
            action,
            context,
        } => run_diagnostic_session(control, lease, quiesced, &state, challenge, context, action),
        ControlRequest::ReceiptList => bounded_receipt_response(ControlResponse::ReceiptList {
            receipts: ReceiptProjection::list(control.store())?,
        }),
        ControlRequest::ReceiptShow { receipt_id } => {
            bounded_receipt_response(ControlResponse::ReceiptShow {
                canonical_receipt: ReceiptProjection::show(control.store(), &receipt_id)?,
            })
        }
        ControlRequest::ReceiptVerify { receipt_id } => {
            ReceiptProjection::verify(control.store(), &receipt_id)?;
            Ok(ControlResponse::ReceiptVerified {
                receipt_id,
                classification: Box::new(state.classification.clone()),
                initialization_evidence: state.initialization.evidence.clone(),
            })
        }
    }
}

fn bounded_receipt_response(response: ControlResponse) -> Result<ControlResponse, Refusal> {
    let bytes =
        serde_jcs::to_vec(&response).map_err(|_| Refusal::new("receipt_projection_failed"))?;
    if bytes.len() > CONTROL_FRAME_LIMIT {
        return Err(Refusal::new("receipt_too_large"));
    }
    Ok(response)
}

fn run_diagnostic_session(
    control: &AuthorityControl,
    lease: &DaemonLease,
    quiesced: &AtomicBool,
    authority_state: &ember_authority::model::PersistentAuthorityState,
    challenge: String,
    context: ember_authority::model::LaunchContext,
    action: ember_authority::model::ActionRequest,
) -> Result<ControlResponse, Refusal> {
    let endpoint_id = uuid::Uuid::new_v4().simple().to_string();
    let endpoint = lease
        .root_path
        .join("sessions")
        .join(format!("{}.sock", &endpoint_id[..16]));
    let mut supervisor = SessionSupervisor::bind(endpoint.clone())?;
    lease.verify_root_identity()?;
    let launch = control.open_diagnostic_session(
        &challenge,
        authority_state.operator_uid,
        &context,
        endpoint.to_string_lossy().into_owned(),
    )?;
    let result = (|| -> Result<ControlResponse, Refusal> {
        let action_bytes =
            serde_jcs::to_vec(&action).map_err(|_| Refusal::new("invalid_request"))?;
        let action_argument = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            action_bytes,
        );
        let reviewed_cli = fs::canonicalize(cli_binary()?)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        let reviewed_digest = identity::executable_digest(&reviewed_cli)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        if reviewed_digest != authority_state.caller_eligibility.executable_digest {
            return Err(Refusal::new("untrusted_launcher"));
        }
        let mut command = Command::new(&reviewed_cli);
        command
            .env_clear()
            .arg("__session-child")
            .arg("--state-root")
            .arg(&lease.root_path)
            .arg("--endpoint")
            .arg(&launch.endpoint)
            .arg("--session-id")
            .arg(&launch.session_id)
            .arg("--execution-binding-id")
            .arg(&launch.execution_binding_id)
            .arg("--action")
            .arg(action_argument)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let pid = supervisor.launch(&mut command)?;
        let pid_version = identity::process_pid_version(pid)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        let launched_identity = identity::process_executable_identity(pid, pid_version)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        if launched_identity != authority_state.caller_eligibility.executable_identity {
            return Err(Refusal::new("untrusted_launcher"));
        }
        lease.verify_root_identity()?;
        control.activate_session(
            &launch.session_id,
            &launch.execution_binding_id,
            pid,
            Some(pid_version),
        )?;

        // Serve the private endpoint until the reviewed child is authenticated.
        // A wrong same-UID peer is refused and the listener keeps serving, so a
        // squatting process cannot starve the child or hang the daemon.
        let deadline = Instant::now() + Duration::from_secs(5);
        let _response = loop {
            let mut session_stream = supervisor.accept_before(deadline)?;
            session_stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| Refusal::new("transport_failed"))?;
            let process = ExecutionBindingAuthority::authenticate_fd(&session_stream)?;
            if Some(process.pid) != supervisor.child_id() {
                let _ = write_frame(
                    &mut session_stream,
                    &SessionActionResponse::Refusal {
                        code: "session_binding_mismatch".into(),
                    },
                );
                continue;
            }
            let session_request: SessionActionRequest = match read_frame(&mut session_stream) {
                Ok(request) => request,
                Err(error) => {
                    let response = SessionActionResponse::Refusal {
                        code: error.code.into(),
                    };
                    write_frame(&mut session_stream, &response)?;
                    drop(session_stream);
                    break response;
                }
            };
            if session_request.session_id != launch.session_id
                || session_request.execution_binding_id != launch.execution_binding_id
            {
                let _ = write_frame(
                    &mut session_stream,
                    &SessionActionResponse::Refusal {
                        code: "session_binding_mismatch".into(),
                    },
                );
                continue;
            }
            lease.verify_root_identity()?;
            let kernel = AuthorityKernel::new(control.store().clone());
            let response = match kernel.submit(&launch.session_id, process, session_request.action)
            {
                Ok(action) => SessionActionResponse::Success {
                    action: Box::new(action),
                },
                Err(error) => {
                    if is_durability_failure(error.code) {
                        quiesced.store(true, Ordering::SeqCst);
                    }
                    SessionActionResponse::Refusal {
                        code: error.code.into(),
                    }
                }
            };
            write_frame(&mut session_stream, &response)?;
            drop(session_stream);
            break response;
        };
        let output = supervisor.wait_with_output()?;
        Ok(ControlResponse::SessionComplete {
            exit_code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    })();
    lease.verify_root_identity()?;
    let close_result = control.close_session(&launch.session_id);
    if let Err(error) = close_result {
        if is_durability_failure(error.code) {
            quiesced.store(true, Ordering::SeqCst);
        }
        return Err(error);
    }
    result
}

fn is_durability_failure(code: &str) -> bool {
    matches!(
        code,
        "state_unavailable" | "journal_unavailable" | "continuity_unavailable" | "restore_failed"
    )
}

fn cli_binary() -> Result<PathBuf, Refusal> {
    let current = std::env::current_exe().map_err(|_| Refusal::new("session_launch_failed"))?;
    let cli = current.with_file_name("ember");
    if !cli.is_file() {
        return Err(Refusal::new("session_launch_failed"));
    }
    Ok(cli)
}

struct DaemonLease {
    _root_directory: File,
    root_path: PathBuf,
    root_identity: (u64, u64),
    _file: File,
    socket_path: PathBuf,
    socket_identity: Option<(u64, u64)>,
}

impl DaemonLease {
    fn acquire(state_root: &Path, socket_path: &Path) -> Result<Self, Refusal> {
        let root_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_root)
            .map_err(|_| Refusal::new("authority_lease_untrusted"))?;
        let root_metadata = root_directory
            .metadata()
            .map_err(|_| Refusal::new("authority_lease_untrusted"))?;
        if !root_metadata.file_type().is_dir()
            || root_metadata.uid() != ember_authority::effective_uid()
            || root_metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(Refusal::new("authority_lease_untrusted"));
        }
        // The directory inode cannot be replaced by unlinking `daemon.lock`.
        // Lock it before touching the lease file or incumbent endpoint.
        let root_locked =
            unsafe { libc::flock(root_directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if root_locked != 0 {
            return Err(Refusal::new("authority_in_use"));
        }
        let root_identity = (root_metadata.dev(), root_metadata.ino());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_root.join("daemon.lock"))
            .map_err(|_| Refusal::new("authority_lease_untrusted"))?;
        let metadata = file
            .metadata()
            .map_err(|_| Refusal::new("authority_lease_untrusted"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != ember_authority::effective_uid()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(Refusal::new("authority_lease_untrusted"));
        }
        // SAFETY: `file` owns a live descriptor and `flock` neither retains the
        // pointer nor accesses Rust-managed memory.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if locked != 0 {
            return Err(Refusal::new("authority_in_use"));
        }
        verify_path_identity(state_root, root_identity)?;
        remove_stale_socket(socket_path)?;
        Ok(Self {
            _root_directory: root_directory,
            root_path: state_root.to_owned(),
            root_identity,
            _file: file,
            socket_path: socket_path.to_owned(),
            socket_identity: None,
        })
    }

    fn verify_root_identity(&self) -> Result<(), Refusal> {
        verify_path_identity(&self.root_path, self.root_identity)
    }

    fn claim_socket(&mut self, path: &Path) -> Result<(), Refusal> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| Refusal::new("authority_endpoint_untrusted"))?;
        if !metadata.file_type().is_socket() || metadata.uid() != ember_authority::effective_uid() {
            return Err(Refusal::new("authority_endpoint_untrusted"));
        }
        self.socket_identity = Some((metadata.dev(), metadata.ino()));
        Ok(())
    }
}

impl Drop for DaemonLease {
    fn drop(&mut self) {
        let Some((dev, ino)) = self.socket_identity else {
            return;
        };
        let Ok(metadata) = fs::symlink_metadata(&self.socket_path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.uid() == ember_authority::effective_uid()
            && (metadata.dev(), metadata.ino()) == (dev, ino)
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn verify_path_identity(path: &Path, expected: (u64, u64)) -> Result<(), Refusal> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Refusal::new("state_unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != ember_authority::effective_uid()
        || metadata.permissions().mode() & 0o777 != 0o700
        || (metadata.dev(), metadata.ino()) != expected
    {
        return Err(Refusal::new("state_unavailable"));
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), Refusal> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Refusal::new("authority_endpoint_untrusted")),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != ember_authority::effective_uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(Refusal::new("authority_endpoint_untrusted"));
    }
    fs::remove_file(path).map_err(|_| Refusal::new("authority_endpoint_untrusted"))
}
