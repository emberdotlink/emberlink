#![deny(unsafe_code)]

use std::{
    env,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ember_authority::{
    control::{ControlClient, ControlOperation, ControlResponse, ControlResult},
    custody::{CustodyContext, DoubleEnvelope, cli_unwrap_outer, cli_unwrap_unlock_challenge},
    daemon::ConfiguredDaemon,
    install_transport::{perform_cli_install, serve_daemon_install},
};
use thiserror::Error;

fn main() {
    if let Err(error) = run() {
        eprintln!("ember: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = utf8_arguments(env::args_os().skip(1))?;
    let command = arguments.first().ok_or("missing command")?.as_str();
    match command {
        "daemon" if arguments.len() == 2 => daemon_command(&arguments[1]),
        "install-daemon" if arguments.len() == 2 => install_daemon(&arguments[1]),
        "install" if arguments.len() == 2 => install_client(&arguments[1]),
        "status" if arguments.len() == 2 => request(&arguments[1], ControlOperation::Status),
        "custody-unlock" if arguments.len() == 2 => custody_unlock(&arguments[1]),
        "grant-revoke" if arguments.len() == 3 => request(
            &arguments[1],
            ControlOperation::GrantRevoke {
                grant_id: arguments[2].clone(),
            },
        ),
        "delegation-revoke" if arguments.len() == 3 => request(
            &arguments[1],
            ControlOperation::DelegationRevoke {
                delegation_id: arguments[2].clone(),
            },
        ),
        _ => Err("invalid command or arguments".into()),
    }
}

#[derive(Debug, Error)]
#[error("command argument {index} is not valid UTF-8")]
struct InvalidUtf8Argument {
    index: usize,
}

fn utf8_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Vec<String>, InvalidUtf8Argument> {
    arguments
        .into_iter()
        .enumerate()
        .map(|(index, argument)| {
            argument
                .into_string()
                .map_err(|_| InvalidUtf8Argument { index: index + 1 })
        })
        .collect()
}

fn install_daemon(request_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    restrict_daemon_umask();
    let result = serve_daemon_install(PathBuf::from(request_path).as_path())?;
    println!("{}", String::from_utf8(serde_jcs::to_vec(&result)?)?);
    Ok(())
}

fn install_client(socket_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let result = perform_cli_install(PathBuf::from(socket_path).as_path())?;
    println!("{}", String::from_utf8(serde_jcs::to_vec(&result)?)?);
    Ok(())
}

/// Runs only in the logged-in user's GUI/bootstrap domain. The Data Protection
/// keychain deliberately does not support a system LaunchDaemon deployment.
fn daemon_command(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    restrict_daemon_umask();
    let now = unix_now()?;
    let uid = ember_authority::effective_uid();
    let state_directory = ember_authority::authority_state_directory(uid)?;
    let expected_config_path = state_directory.join("emberd.json");
    if Path::new(config_path) != expected_config_path {
        return Err(format!(
            "daemon config path must be {}",
            expected_config_path.display()
        )
        .into());
    }
    let mut daemon = ConfiguredDaemon::load(expected_config_path, uid, &state_directory, now)?;
    loop {
        daemon.serve_once()?;
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[allow(unsafe_code)]
fn restrict_daemon_umask() {
    // The daemon is single-threaded and sets this once before creating any
    // filesystem-backed socket, so no node is ever born group/world writable
    // under an ambient launcher umask.
    unsafe {
        libc::umask(0o077);
    }
}

fn request(socket: &str, operation: ControlOperation) -> Result<(), Box<dyn std::error::Error>> {
    print_response(ControlClient::new(socket)?.request(operation)?)
}

fn custody_unlock(socket: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = ControlClient::new(socket)?;
    let begin = success_value(client.request(ControlOperation::CustodyUnlockBegin)?)?;
    let sealed = BASE64.decode(
        begin
            .get("sealed_envelope_base64")
            .and_then(|value| value.as_str())
            .ok_or("unlock response omitted sealed envelope")?,
    )?;
    let context: CustodyContext = serde_json::from_value(
        begin
            .get("custody_context")
            .cloned()
            .ok_or("unlock response omitted custody context")?,
    )?;
    let unlock_id_text = begin
        .get("unlock_id")
        .and_then(|value| value.as_str())
        .ok_or("unlock response omitted unlock ID")?;
    let unlock_id = uuid::Uuid::parse_str(unlock_id_text)?;
    if unlock_id.is_nil() || unlock_id.to_string() != unlock_id_text {
        return Err("unlock response contained a noncanonical unlock ID".into());
    }
    let encrypted_challenge = BASE64.decode(
        begin
            .get("encrypted_challenge_base64")
            .and_then(|value| value.as_str())
            .ok_or("unlock response omitted encrypted challenge")?,
    )?;
    let envelope = DoubleEnvelope::decode(&sealed, &context)?;
    let relayed_inner = cli_unwrap_outer(&envelope, &context)?;
    let decrypted_challenge =
        cli_unwrap_unlock_challenge(&envelope, &context, unlock_id, &encrypted_challenge)?;
    print_response(client.request(ControlOperation::CustodyUnlockComplete {
        unlock_id: unlock_id.to_string(),
        decrypted_challenge_base64: BASE64.encode(*decrypted_challenge),
        relayed_inner_base64: BASE64.encode(&*relayed_inner),
    })?)
}

fn success_value(
    response: ControlResponse,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    match response.result {
        ControlResult::Success { ok: true, result } => Ok(result),
        ControlResult::Error { error, .. } => {
            Err(format!("{}: {}", error.code, error.message).into())
        }
        _ => Err("control response has inconsistent result tag".into()),
    }
}

fn print_response(response: ControlResponse) -> Result<(), Box<dyn std::error::Error>> {
    let refusal = match &response.result {
        ControlResult::Error { error, .. } => Some(format!("{}: {}", error.code, error.message)),
        ControlResult::Success { ok: true, .. } => None,
        _ => Some("control response has inconsistent result tag".to_owned()),
    };
    println!("{}", String::from_utf8(serde_jcs::to_vec(&response)?)?);
    match refusal {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}
fn unix_now() -> Result<i64, io::Error> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_secs()).map_err(|_| io::Error::other("system clock overflow"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt as _;

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_argument_is_rejected_without_panicking() {
        let error =
            utf8_arguments([OsString::from("status"), OsString::from_vec(vec![0xff])]).unwrap_err();

        assert_eq!(error.index, 2);
        assert_eq!(error.to_string(), "command argument 2 is not valid UTF-8");
    }
}
