use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ember_authority::{
    AUTHORITY_STATE_DIRECTORY,
    audit::now_unix,
    control::{AuthorityControl, InitializationReceipt},
    diagnostic_bootstrap::{build_request, validate_existing_state_root, validate_new_state_root},
    ipc::{
        ControlRequest, ControlResponse, SessionActionRequest, SessionActionResponse,
        read_control_frame, read_frame, write_control_frame, write_frame,
    },
    model::{ACTION_REQUEST_SCHEMA, ActionRef, ActionRequest, DiagnosticInput, LaunchContext},
    runtime_presence::ExecutionBindingAuthority,
};
use std::{
    fs,
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match dispatch(&args) {
        Ok(code) => code,
        Err(code) => code,
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn dispatch(args: &[String]) -> Result<i32, i32> {
    if args.first().map(String::as_str) == Some("__session-child") {
        return session_child(&args[1..]);
    }
    let explicit_state_dir = args.first().map(String::as_str) == Some("--state-dir");
    if !explicit_state_dir && args.first().map(String::as_str) == Some("init") {
        return refuse("state_root_unavailable");
    }
    let (root, args) = if explicit_state_dir {
        let root = args
            .get(1)
            .map(PathBuf::from)
            .ok_or_else(|| report_code("state_root_unavailable"))?;
        (root, &args[2..])
    } else {
        (default_state_dir()?, args)
    };
    match args.first().map(String::as_str) {
        Some("init") => init_command(&root, &args[1..]),
        Some("status") if args.len() == 2 && args[1] == "--json" => status_command(&root),
        Some("session") => session_command(&root, &args[1..]),
        Some("receipt") => receipt_command(&root, &args[1..]),
        Some("action") => refuse("session_required"),
        Some("--help" | "-h") | None => {
            println!(
                "usage: ember [--state-dir <absolute-path>] <init diagnostic|status|session open|receipt list|show|verify>"
            );
            Ok(0)
        }
        _ => refuse("unknown_command"),
    }
}

#[derive(serde::Serialize)]
struct InitializationOutput {
    schema: &'static str,
    state: &'static str,
    receipt: InitializationReceipt,
    classification: ember_authority::model::ProductClassification,
    evidence: ember_authority::model::InitializationEvidence,
    action_definition_digest: String,
}

fn init_command(root: &Path, args: &[String]) -> Result<i32, i32> {
    let project = match args {
        [diagnostic, project_flag, project]
            if diagnostic == "diagnostic" && project_flag == "--project" =>
        {
            PathBuf::from(project)
        }
        _ => return refuse("invalid_initialization_command"),
    };
    validate_new_state_root(root).map_err(report_refusal)?;
    let cli = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| report_code("bootstrap_artifact_invalid"))?;
    let daemon = cli.with_file_name("emberd");
    let request = build_request(&project, &cli, &daemon, now_unix()).map_err(report_refusal)?;
    let action_definition_digest = request.records.action_definitions[0]
        .action_definition_digest
        .clone();
    let (control, receipt) = AuthorityControl::initialize(root, request).map_err(report_refusal)?;
    let state = control.store().snapshot().map_err(report_refusal)?;
    print_json(&InitializationOutput {
        schema: "ember.initialization-result/v1",
        state: "initialized",
        receipt,
        classification: state.classification,
        evidence: state.initialization.evidence,
        action_definition_digest,
    })?;
    Ok(0)
}

fn status_command(root: &Path) -> Result<i32, i32> {
    validate_existing_state_root(root).map_err(report_refusal)?;
    let mut stream = trusted_control_stream(root)?;
    write_control_frame(&mut stream, &ControlRequest::Status).map_err(report_refusal)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| report_code("transport_failed"))?;
    match read_control_frame::<ControlResponse>(&mut stream).map_err(report_refusal)? {
        ControlResponse::Status { status } => print_json(&status)?,
        ControlResponse::Refusal { code } => return refuse(&code),
        _ => return refuse("unexpected_daemon_response"),
    }
    Ok(0)
}

fn session_command(root: &Path, args: &[String]) -> Result<i32, i32> {
    validate_existing_state_root(root).map_err(report_refusal)?;
    let separator = args
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| report_code("invalid_session_command"))?;
    let before = &args[..separator];
    if before.len() != 4
        || before[0] != "open"
        || before[1] != "diagnostic"
        || before[2] != "--challenge"
    {
        return refuse("invalid_session_command");
    }
    let challenge = before[3].clone();
    let tail = &args[separator + 1..];
    if tail.first().map(String::as_str) != Some("ember") {
        return Err(report_code("invalid_action_command"));
    }
    let tail = &tail[1..];
    let action = parse_action(tail)?;
    if action.input.challenge != challenge {
        return refuse("uncovered_need");
    }
    let current = fs::canonicalize(
        std::env::current_dir().map_err(|_| report_code("launch_context_unavailable"))?,
    )
    .map_err(|_| report_code("launch_context_unavailable"))?;
    let current = current
        .to_str()
        .ok_or_else(|| report_code("launch_context_unavailable"))?
        .to_owned();
    let context = LaunchContext {
        project_root: current.clone(),
        worktree: current,
    };
    let mut stream = trusted_control_stream(root)?;
    write_control_frame(
        &mut stream,
        &ControlRequest::OpenDiagnostic {
            challenge,
            action,
            context,
        },
    )
    .map_err(report_refusal)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| report_code("transport_failed"))?;
    match read_control_frame::<ControlResponse>(&mut stream).map_err(report_refusal)? {
        ControlResponse::SessionComplete {
            exit_code,
            stdout,
            stderr,
        } => {
            print!("{stdout}");
            eprint!("{stderr}");
            Ok(exit_code)
        }
        ControlResponse::Refusal { code } => refuse(&code),
        ControlResponse::Pong => refuse("invalid_response"),
        _ => refuse("unexpected_daemon_response"),
    }
}

fn parse_action(args: &[String]) -> Result<ActionRequest, i32> {
    let (digest, input_index) = match args {
        [action, run, _, digest_flag, digest, input_flag, _]
            if action == "action"
                && run == "run"
                && digest_flag == "--definition-digest"
                && input_flag == "--input" =>
        {
            (Some(digest.clone()), 6)
        }
        [action, run, _, input_flag, _]
            if action == "action" && run == "run" && input_flag == "--input" =>
        {
            (None, 4)
        }
        _ => return Err(report_code("invalid_action_command")),
    };
    let action_ref = ActionRef::parse(&args[2]).map_err(report_refusal)?;
    let input: DiagnosticInput = ember_authority::audit::decode_canonical(
        args[input_index].as_bytes(),
        ember_authority::ipc::FRAME_LIMIT,
        "invalid_input",
    )
    .map_err(report_refusal)?;
    input.validate().map_err(report_refusal)?;
    Ok(ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.into(),
        submission_id: uuid::Uuid::new_v4().to_string(),
        action_ref,
        definition_digest: digest,
        input,
    })
}

fn session_child(args: &[String]) -> Result<i32, i32> {
    let endpoint = argument(args, "--endpoint")?;
    let session_id = argument(args, "--session-id")?;
    let execution_binding_id = argument(args, "--execution-binding-id")?;
    let action_encoded = argument(args, "--action")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(action_encoded)
        .map_err(|_| report_code("invalid_request"))?;
    if bytes.len() > ember_authority::ipc::FRAME_LIMIT {
        return refuse("frame_too_large");
    }
    let action: ActionRequest = ember_authority::audit::decode_canonical(
        &bytes,
        ember_authority::ipc::FRAME_LIMIT,
        "invalid_request",
    )
    .map_err(report_refusal)?;
    let root = PathBuf::from(argument(args, "--state-root")?);
    validate_existing_state_root(&root).map_err(report_refusal)?;
    let mut stream = trusted_daemon_stream(&root, Path::new(endpoint), "session_endpoint_failed")?;
    write_frame(
        &mut stream,
        &SessionActionRequest {
            session_id: session_id.into(),
            execution_binding_id: execution_binding_id.into(),
            action,
        },
    )
    .map_err(report_refusal)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| report_code("transport_failed"))?;
    match read_frame::<SessionActionResponse>(&mut stream).map_err(report_refusal)? {
        SessionActionResponse::Success { action } => {
            print_json(&action)?;
            Ok(0)
        }
        SessionActionResponse::Refusal { code } => refuse(&code),
    }
}

fn receipt_command(root: &Path, args: &[String]) -> Result<i32, i32> {
    validate_existing_state_root(root).map_err(report_refusal)?;
    // Every Receipt read is an authenticated daemon call: the CLI never opens
    // private authority state (and its Device keys) in-process.
    let request = match args.first().map(String::as_str) {
        Some("list") if args.len() == 2 && args[1] == "--json" => ControlRequest::ReceiptList,
        Some("show") if args.len() == 2 => ControlRequest::ReceiptShow {
            receipt_id: args[1].clone(),
        },
        Some("verify") if args.len() == 2 => ControlRequest::ReceiptVerify {
            receipt_id: args[1].clone(),
        },
        _ => return refuse("invalid_receipt_command"),
    };
    let mut stream = trusted_control_stream(root)?;
    write_control_frame(&mut stream, &request).map_err(report_refusal)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| report_code("transport_failed"))?;
    match read_control_frame::<ControlResponse>(&mut stream).map_err(report_refusal)? {
        ControlResponse::ReceiptList { receipts } => print_json(&receipts)?,
        ControlResponse::ReceiptShow { canonical_receipt } => println!("{canonical_receipt}"),
        ControlResponse::ReceiptVerified {
            receipt_id,
            classification,
            initialization_evidence,
        } => print_json(&serde_json::json!({
            "state": "verified",
            "receipt_id": receipt_id,
            "classification": classification,
            "initialization_evidence": initialization_evidence,
        }))?,
        ControlResponse::Refusal { code } => return refuse(&code),
        _ => return refuse("unexpected_daemon_response"),
    }
    Ok(0)
}

fn default_state_dir() -> Result<PathBuf, i32> {
    let home = std::env::var_os("HOME").ok_or_else(|| report_code("state_root_unavailable"))?;
    let root = fs::canonicalize(PathBuf::from(home))
        .map_err(|_| report_code("state_root_unavailable"))?
        .join(AUTHORITY_STATE_DIRECTORY);
    if !root.is_absolute() {
        return Err(report_code("state_root_unavailable"));
    }
    Ok(root)
}

fn trusted_control_stream(root: &Path) -> Result<UnixStream, i32> {
    trusted_daemon_stream(root, &root.join("control.sock"), "daemon_unavailable")
}

fn trusted_daemon_stream(
    root: &Path,
    socket: &Path,
    unavailable_code: &'static str,
) -> Result<UnixStream, i32> {
    let expected_uid = ember_authority::effective_uid();
    let canonical_root =
        fs::canonicalize(root).map_err(|_| report_code("state_root_unavailable"))?;
    if canonical_root != root {
        return Err(report_code("state_root_untrusted"));
    }
    let root_metadata =
        fs::metadata(&canonical_root).map_err(|_| report_code("state_root_unavailable"))?;
    if root_metadata.uid() != expected_uid || root_metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(report_code("state_root_untrusted"));
    }
    let parent = socket
        .parent()
        .and_then(|value| fs::canonicalize(value).ok())
        .ok_or_else(|| report_code("authority_endpoint_untrusted"))?;
    let sessions = canonical_root.join("sessions");
    if parent != canonical_root && parent != sessions {
        return Err(report_code("authority_endpoint_untrusted"));
    }
    if parent == sessions {
        let metadata =
            fs::metadata(&sessions).map_err(|_| report_code("authority_endpoint_untrusted"))?;
        if metadata.uid() != expected_uid || metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(report_code("authority_endpoint_untrusted"));
        }
    }
    let socket = parent.join(
        socket
            .file_name()
            .ok_or_else(|| report_code("authority_endpoint_untrusted"))?,
    );
    let metadata = fs::symlink_metadata(&socket).map_err(|_| report_code(unavailable_code))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(report_code("authority_endpoint_untrusted"));
    }
    let stream = UnixStream::connect(&socket).map_err(|_| report_code(unavailable_code))?;
    let peer = ExecutionBindingAuthority::authenticate_fd(&stream).map_err(report_refusal)?;
    if peer.uid != expected_uid {
        return Err(report_code("authority_endpoint_untrusted"));
    }
    // Pin the serving process to the initialized release manifest without
    // decoding authority owner state or Device custody in the client.
    let expected_daemon = std::env::current_exe()
        .map(|path| path.with_file_name("emberd"))
        .and_then(fs::canonicalize)
        .map_err(|_| report_code("authority_endpoint_untrusted"))?;
    let installed = ember_authority::audit::DurableStore::installed_daemon_binding(&canonical_root)
        .map_err(|_| report_code("authority_endpoint_untrusted"))?;
    let expected_digest = ember_authority::identity::executable_digest(&expected_daemon)
        .map_err(|_| report_code("authority_endpoint_untrusted"))?;
    if expected_digest != installed.executable_digest {
        return Err(report_code("authority_endpoint_untrusted"));
    }
    let observed_daemon =
        ember_authority::identity::process_executable_path(peer.pid, peer.pid_version)
            .and_then(fs::canonicalize)
            .map_err(|_| report_code("authority_endpoint_untrusted"))?;
    let observed_identity =
        ember_authority::identity::process_executable_identity(peer.pid, peer.pid_version)
            .map_err(|_| report_code("authority_endpoint_untrusted"))?;
    let installed_identity = installed
        .executable_identity
        .ok_or_else(|| report_code("authority_endpoint_untrusted"))?;
    if observed_daemon != expected_daemon || observed_identity != installed_identity {
        return Err(report_code("authority_endpoint_untrusted"));
    }
    Ok(stream)
}

fn argument<'a>(args: &'a [String], name: &str) -> Result<&'a str, i32> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| report_code("invalid_session_command"))
}

fn print_json(value: &impl serde::Serialize) -> Result<(), i32> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| report_code("serialization_failed"))?;
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

fn refuse(code: &str) -> Result<i32, i32> {
    Err(report_code(code))
}

fn report_refusal(refusal: ember_authority::model::Refusal) -> i32 {
    report_code(refusal.code)
}

fn report_code(code: &str) -> i32 {
    eprintln!("refused: {code}");
    1
}
