use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ember_authority::{
    AUTHORITY_STATE_DIRECTORY,
    ipc::{
        ControlRequest, ControlResponse, SessionActionRequest, SessionActionResponse, read_frame,
        write_frame,
    },
    model::{ACTION_REQUEST_SCHEMA, ActionRef, ActionRequest, DiagnosticInput},
};
use std::{os::unix::net::UnixStream, path::PathBuf};

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
    match args.first().map(String::as_str) {
        Some("session") => session_command(&args[1..]),
        Some("receipt") => receipt_command(&args[1..]),
        Some("action") => refuse("missing_session"),
        Some("__session-child") => session_child(&args[1..]),
        Some("--help" | "-h") | None => {
            println!("usage: ember <session open|receipt list|show|verify>");
            Ok(0)
        }
        _ => refuse("unknown_command"),
    }
}

fn session_command(args: &[String]) -> Result<i32, i32> {
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
    let mut tail = &args[separator + 1..];
    if tail.first().map(String::as_str) == Some("ember") {
        tail = &tail[1..];
    }
    let action = parse_action(tail)?;
    if action.input.challenge != challenge {
        return refuse("uncovered_need");
    }
    let root = default_state_dir();
    let mut stream = UnixStream::connect(root.join("control.sock"))
        .map_err(|_| report_code("daemon_unavailable"))?;
    write_frame(
        &mut stream,
        &ControlRequest::OpenDiagnostic { challenge, action },
    )
    .map_err(report_refusal)?;
    match read_frame::<ControlResponse>(&mut stream).map_err(report_refusal)? {
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
    if args.len() != 8
        || args[0] != "action"
        || args[1] != "run"
        || args[3] != "--definition-digest"
        || args[5] != "--input"
    {
        return Err(report_code("invalid_action_command"));
    }
    let action_ref = ActionRef::parse(&args[2]).map_err(report_refusal)?;
    let input: DiagnosticInput =
        serde_json::from_str(&args[6]).map_err(|_| report_code("invalid_input"))?;
    input.validate().map_err(report_refusal)?;
    if args[7] != "--json" {
        return Err(report_code("invalid_action_command"));
    }
    Ok(ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.into(),
        submission_id: uuid::Uuid::new_v4().to_string(),
        action_ref,
        definition_digest: args[4].clone(),
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
    let mut stream =
        UnixStream::connect(endpoint).map_err(|_| report_code("session_endpoint_failed"))?;
    write_frame(
        &mut stream,
        &SessionActionRequest {
            session_id: session_id.into(),
            execution_binding_id: execution_binding_id.into(),
            action,
        },
    )
    .map_err(report_refusal)?;
    match read_frame::<SessionActionResponse>(&mut stream).map_err(report_refusal)? {
        SessionActionResponse::Success { action } => {
            print_json(&action)?;
            Ok(0)
        }
        SessionActionResponse::Refusal { code } => refuse(&code),
    }
}

fn receipt_command(args: &[String]) -> Result<i32, i32> {
    let request = match args.first().map(String::as_str) {
        Some("list") if args.len() == 2 && args[1] == "--json" => ControlRequest::ReceiptList,
        Some("show") if args.len() == 3 && args[2] == "--json" => ControlRequest::ReceiptShow {
            receipt_id: args[1].clone(),
        },
        Some("verify") if args.len() == 3 && args[2] == "--json" => ControlRequest::ReceiptVerify {
            receipt_id: args[1].clone(),
        },
        _ => return refuse("invalid_receipt_command"),
    };
    let root = default_state_dir();
    let mut stream = UnixStream::connect(root.join("control.sock"))
        .map_err(|_| report_code("daemon_unavailable"))?;
    write_frame(&mut stream, &request).map_err(report_refusal)?;
    match read_frame::<ControlResponse>(&mut stream).map_err(report_refusal)? {
        ControlResponse::ReceiptList { receipts } => print_json(&receipts)?,
        ControlResponse::ReceiptShow { canonical_receipt } => println!("{canonical_receipt}"),
        ControlResponse::ReceiptVerified { receipt_id } => {
            print_json(&serde_json::json!({"receipt_id": receipt_id, "valid": true}))?
        }
        ControlResponse::Refusal { code } => return refuse(&code),
        _ => return refuse("unexpected_daemon_response"),
    }
    Ok(0)
}

fn default_state_dir() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(AUTHORITY_STATE_DIRECTORY)
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
