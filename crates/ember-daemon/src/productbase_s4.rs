use ember_authority::{
    audit::sha256,
    control::AuthorityControl,
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
    fs,
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub fn run(state_root: &Path) -> Result<(), String> {
    let control = AuthorityControl::restore(state_root).map_err(|error| error.to_string())?;
    verify_daemon_executable(&control).map_err(|error| error.to_string())?;
    let socket_path = state_root.join("control.sock");
    remove_socket(&socket_path);
    let listener = UnixListener::bind(&socket_path).map_err(|error| error.to_string())?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    println!(
        "emberd ProductBase authority ready: {}",
        socket_path.display()
    );
    let quiesced = AtomicBool::new(false);
    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("emberd: accept failed: {error}");
                continue;
            }
        };
        let response = match handle_control(&control, state_root, &quiesced, &mut stream) {
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
        if quiesced.load(Ordering::SeqCst) {
            break;
        }
    }
    Ok(())
}

fn verify_daemon_executable(control: &AuthorityControl) -> Result<(), Refusal> {
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let digest =
        sha256(&fs::read(executable).map_err(|_| Refusal::new("process_identity_unavailable"))?);
    if digest != control.store().snapshot()?.daemon_executable_digest {
        return Err(Refusal::new("untrusted_daemon"));
    }
    Ok(())
}

fn handle_control(
    control: &AuthorityControl,
    state_root: &Path,
    quiesced: &AtomicBool,
    stream: &mut UnixStream,
) -> Result<ControlResponse, Refusal> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Refusal::new("transport_failed"))?;
    let request: ControlRequest = read_control_frame(stream)?;
    let peer = ExecutionBindingAuthority::authenticate_fd(stream)?;
    let state = control.store().snapshot()?;
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
    let reviewed_digest =
        sha256(&fs::read(&reviewed_cli).map_err(|_| Refusal::new("process_identity_unavailable"))?);
    let reviewed_identity = identity::executable_identity(&reviewed_cli)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    let observed_identity = identity::process_executable_identity(peer.pid, peer.pid_version)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    if reviewed_digest != state.caller_eligibility.executable_digest
        || observed_identity != reviewed_identity
    {
        return Err(Refusal::new("untrusted_launcher"));
    }
    match request {
        ControlRequest::Ping => Ok(ControlResponse::Pong),
        ControlRequest::OpenDiagnostic {
            challenge,
            action,
            context,
        } => run_diagnostic_session(
            control, state_root, quiesced, peer.uid, challenge, context, action,
        ),
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
            Ok(ControlResponse::ReceiptVerified { receipt_id })
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
    state_root: &Path,
    quiesced: &AtomicBool,
    peer_uid: u32,
    challenge: String,
    context: ember_authority::model::LaunchContext,
    action: ember_authority::model::ActionRequest,
) -> Result<ControlResponse, Refusal> {
    let endpoint_id = uuid::Uuid::new_v4().simple().to_string();
    let endpoint = state_root
        .join("sessions")
        .join(format!("{}.sock", &endpoint_id[..16]));
    let mut supervisor = SessionSupervisor::bind(endpoint.clone())?;

    let launch = control.open_diagnostic_session(
        &challenge,
        peer_uid,
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
        let mut command = Command::new(cli_binary()?);
        command
            .env_clear()
            .arg("__session-child")
            .arg("--state-root")
            .arg(state_root)
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
            let kernel = AuthorityKernel::new(control.store().clone());
            let response = match kernel.submit(&launch.session_id, process, session_request.action)
            {
                Ok(action) => SessionActionResponse::Success { action },
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

fn remove_socket(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}
