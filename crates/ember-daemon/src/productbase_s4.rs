use ember_authority::{
    audit::sha256,
    control::AuthorityControl,
    identity,
    ipc::{
        ControlRequest, ControlResponse, SessionActionRequest, SessionActionResponse, read_frame,
        write_frame,
    },
    kernel::AuthorityKernel,
    model::Refusal,
    receipt::ReceiptProjection,
    runtime_presence::ExecutionBindingAuthority,
};
use std::{
    fs,
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn run(state_root: &Path) -> Result<(), String> {
    let control = AuthorityControl::restore(state_root).map_err(|error| error.to_string())?;
    let socket_path = state_root.join("control.sock");
    remove_socket(&socket_path);
    let listener = UnixListener::bind(&socket_path).map_err(|error| error.to_string())?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    println!(
        "emberd ProductBase authority ready: {}",
        socket_path.display()
    );
    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("emberd: accept failed: {error}");
                continue;
            }
        };
        let response = match handle_control(&control, state_root, &mut stream) {
            Ok(response) => response,
            Err(error) => ControlResponse::Refusal {
                code: error.code.into(),
            },
        };
        if let Err(error) = write_frame(&mut stream, &response) {
            eprintln!("emberd: response failed: {error}");
        }
    }
    Ok(())
}

fn handle_control(
    control: &AuthorityControl,
    state_root: &Path,
    stream: &mut UnixStream,
) -> Result<ControlResponse, Refusal> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Refusal::new("transport_failed"))?;
    let request: ControlRequest = read_frame(stream)?;
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
    let observed_digest =
        sha256(&fs::read(&observed_cli).map_err(|_| Refusal::new("process_identity_unavailable"))?);
    if observed_digest != state.caller_eligibility.executable_digest {
        return Err(Refusal::new("untrusted_launcher"));
    }
    match request {
        ControlRequest::Ping => Ok(ControlResponse::Pong),
        ControlRequest::OpenDiagnostic { challenge, action } => {
            run_diagnostic_session(control, state_root, challenge, action)
        }
        ControlRequest::ReceiptList => Ok(ControlResponse::ReceiptList {
            receipts: ReceiptProjection::list(control.store())?,
        }),
        ControlRequest::ReceiptShow { receipt_id } => Ok(ControlResponse::ReceiptShow {
            canonical_receipt: ReceiptProjection::show(control.store(), &receipt_id)?,
        }),
        ControlRequest::ReceiptVerify { receipt_id } => {
            ReceiptProjection::verify(control.store(), &receipt_id)?;
            Ok(ControlResponse::ReceiptVerified { receipt_id })
        }
    }
}

fn run_diagnostic_session(
    control: &AuthorityControl,
    state_root: &Path,
    challenge: String,
    action: ember_authority::model::ActionRequest,
) -> Result<ControlResponse, Refusal> {
    let sessions = state_root.join("sessions");
    fs::create_dir_all(&sessions).map_err(|_| Refusal::new("state_unavailable"))?;
    fs::set_permissions(&sessions, fs::Permissions::from_mode(0o700))
        .map_err(|_| Refusal::new("state_unavailable"))?;
    let endpoint = sessions.join(format!("{}.sock", uuid::Uuid::new_v4()));
    let listener =
        UnixListener::bind(&endpoint).map_err(|_| Refusal::new("session_endpoint_failed"))?;
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))
        .map_err(|_| Refusal::new("session_endpoint_failed"))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| Refusal::new("session_endpoint_failed"))?;

    let launch = control.open_diagnostic_session(
        &challenge,
        control.store().snapshot()?.operator_uid,
        endpoint.to_string_lossy().into_owned(),
    )?;
    let mut child = None;
    let result = (|| -> Result<ControlResponse, Refusal> {
        let action_bytes =
            serde_jcs::to_vec(&action).map_err(|_| Refusal::new("invalid_request"))?;
        let action_argument = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            action_bytes,
        );
        let spawned = Command::new(cli_binary()?)
            .arg("__session-child")
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
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Refusal::new("session_launch_failed"))?;
        let pid = spawned.id();
        child = Some(spawned);
        let pid_version = identity::process_pid_version(pid)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        control.activate_session(
            &launch.session_id,
            &launch.execution_binding_id,
            pid,
            Some(pid_version),
        )?;

        let mut session_stream = accept_before(&listener, Instant::now() + Duration::from_secs(5))?;
        session_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Refusal::new("transport_failed"))?;
        let session_request: SessionActionRequest = read_frame(&mut session_stream)?;
        let process = ExecutionBindingAuthority::authenticate_fd(&session_stream)?;
        let response = if session_request.session_id != launch.session_id
            || session_request.execution_binding_id != launch.execution_binding_id
        {
            SessionActionResponse::Refusal {
                code: "session_binding_mismatch".into(),
            }
        } else {
            let kernel = AuthorityKernel::new(control.store().clone());
            match kernel.submit(&launch.session_id, process, session_request.action) {
                Ok(action) => SessionActionResponse::Success { action },
                Err(error) => SessionActionResponse::Refusal {
                    code: error.code.into(),
                },
            }
        };
        write_frame(&mut session_stream, &response)?;
        drop(session_stream);
        let output = child
            .take()
            .ok_or_else(|| Refusal::new("session_launch_failed"))?
            .wait_with_output()
            .map_err(|_| Refusal::new("session_launch_failed"))?;
        Ok(ControlResponse::SessionComplete {
            exit_code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    })();
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
    let close_result = control.close_session(&launch.session_id);
    remove_socket(&endpoint);
    close_result?;
    result
}

fn accept_before(listener: &UnixListener, deadline: Instant) -> Result<UnixStream, Refusal> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Refusal::new("session_launch_failed"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(Refusal::new("session_endpoint_failed")),
        }
    }
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
