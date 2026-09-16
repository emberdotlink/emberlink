#![deny(unsafe_code)]

use std::io::Read as _;

use ember_authority::host_client::{self, AdapterRole};
use zeroize::Zeroizing;

const SESSION_ENDPOINT_FD_ENV: &str = "EMBER_SESSION_ENDPOINT_FD";
const MAX_SESSION_ENDPOINT_BYTES: u64 = 64 * 1024;

pub fn session_endpoint() -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if std::env::args_os().len() != 1 {
        return Err("Session adapters accept only an inherited endpoint");
    }
    let raw_fd = std::env::var(SESSION_ENDPOINT_FD_ENV)
        .map_err(|_| "missing inherited Session endpoint")?
        .parse::<u32>()
        .map_err(|_| "invalid inherited Session endpoint")?;
    if raw_fd < 3 {
        return Err("invalid inherited Session endpoint");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(format!("/dev/fd/{raw_fd}"))
        .map_err(|_| "could not open inherited Session endpoint")?
        .take(MAX_SESSION_ENDPOINT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read inherited Session endpoint")?;
    if bytes.is_empty() || bytes.len() > MAX_SESSION_ENDPOINT_BYTES as usize || bytes.contains(&0) {
        return Err("invalid inherited Session endpoint");
    }
    Ok(bytes)
}

pub fn run(program: &str, role: AdapterRole) {
    let endpoint = match session_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            eprintln!("{program}: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = host_client::run_inherited(role, &endpoint) {
        let code = if matches!(error, host_client::HostClientError::WrongRole) {
            4
        } else {
            1
        };
        eprintln!("{program}: {error}");
        std::process::exit(code);
    }
}
