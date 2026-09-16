use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    process::ExitCode,
    time::Duration,
};

use ember_authority::principal::ExecutableDigest;
use zeroize::Zeroizing;

const TOKEN_SOCKET_ENV: &str = "EMBER_ASKPASS_SOCKET";
const EXPECTED_ORIGIN_ENV: &str = "EMBER_ASKPASS_ORIGIN";
const SERVER_PID_ENV: &str = "EMBER_ASKPASS_SERVER_PID";
const SERVER_PID_VERSION_ENV: &str = "EMBER_ASKPASS_SERVER_PID_VERSION";
const SERVER_EXECUTABLE_DIGEST_ENV: &str = "EMBER_ASKPASS_SERVER_EXECUTABLE_DIGEST_SHA256";
const MAX_TOKEN_BYTES: u64 = 16 * 1024;

fn main() -> ExitCode {
    let Some(prompt) = env::args_os().nth(1) else {
        return ExitCode::from(2);
    };
    let Some(origin) = env::var_os(EXPECTED_ORIGIN_ENV) else {
        return ExitCode::from(1);
    };
    let (prompt, origin) = (prompt.to_string_lossy(), origin.to_string_lossy());
    let Some(response) = response_for_prompt(&prompt, &origin) else {
        return ExitCode::from(2);
    };
    let mut stdout = io::stdout().lock();

    if response == PromptResponse::Username {
        return match stdout.write_all(b"x-access-token") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }

    let Some(socket) = env::var_os(TOKEN_SOCKET_ENV) else {
        return ExitCode::from(1);
    };
    let Some(expected_server) = parse_expected_server_identity(
        env::var_os(SERVER_PID_ENV).as_deref(),
        env::var_os(SERVER_PID_VERSION_ENV).as_deref(),
        env::var_os(SERVER_EXECUTABLE_DIGEST_ENV).as_deref(),
    ) else {
        return ExitCode::from(1);
    };
    if !Path::new(&socket).is_absolute() {
        return ExitCode::from(1);
    }
    match echo_socket_token(Path::new(&socket), expected_server, &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromptResponse {
    Username,
    Password,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedServerIdentity {
    pid: u32,
    pid_version: u64,
    executable_digest: ExecutableDigest,
}

fn parse_expected_server_identity(
    pid: Option<&OsStr>,
    pid_version: Option<&OsStr>,
    executable_digest: Option<&OsStr>,
) -> Option<ExpectedServerIdentity> {
    let pid = canonical_decimal(pid)?
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)?;
    let pid_version = canonical_decimal(pid_version)?
        .parse::<u64>()
        .ok()
        .filter(|pid_version| *pid_version != 0)?;

    let executable_digest_value = executable_digest?.to_str()?;
    if executable_digest_value.len() != 64
        || !executable_digest_value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let executable_digest = ExecutableDigest::from_sha256_hex(executable_digest_value).ok()?;

    Some(ExpectedServerIdentity {
        pid,
        pid_version,
        executable_digest,
    })
}

fn canonical_decimal(value: Option<&OsStr>) -> Option<&str> {
    let value = value?.to_str()?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(value)
}

fn response_for_prompt(prompt: &str, expected_origin: &str) -> Option<PromptResponse> {
    let repository = expected_origin.strip_prefix("https://github.com/")?;
    let mut components = repository.split('/');
    let owner = components.next()?;
    let name = components.next()?;
    if owner.is_empty()
        || name.strip_suffix(".git").is_none_or(str::is_empty)
        || components.next().is_some()
        || expected_origin.contains('@')
        || expected_origin.contains('?')
        || expected_origin.contains('#')
    {
        return None;
    }

    if prompt == format!("Username for '{expected_origin}': ") {
        return Some(PromptResponse::Username);
    }
    let password_origin = format!("https://x-access-token@github.com/{repository}");
    if prompt == format!("Password for '{password_origin}': ") {
        return Some(PromptResponse::Password);
    }
    None
}

fn echo_socket_token(
    socket: &Path,
    expected_server: ExpectedServerIdentity,
    writer: &mut impl Write,
) -> io::Result<()> {
    echo_socket_token_with(socket, expected_server, writer, authenticate_server)
}

fn echo_socket_token_with(
    socket: &Path,
    expected_server: ExpectedServerIdentity,
    writer: &mut impl Write,
    authenticate: impl FnOnce(&UnixStream, ExpectedServerIdentity) -> io::Result<()>,
) -> io::Result<()> {
    let before = validate_socket(socket)?;
    let mut authority = UnixStream::connect(socket)?;
    let after = validate_socket(socket)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential socket changed while connecting",
        ));
    }
    authenticate(&authority, expected_server)?;
    authority.set_read_timeout(Some(Duration::from_secs(10)))?;
    echo_token(&mut authority, writer)
}

fn authenticate_server(
    authority: &UnixStream,
    expected_server: ExpectedServerIdentity,
) -> io::Result<()> {
    let peer = ember_authority::identity::peer_identity(authority)?;
    if peer.euid() != ember_authority::effective_uid()
        || peer.pid() != expected_server.pid
        || peer.pid_version() != expected_server.pid_version
        || peer.executable_digest() != expected_server.executable_digest
        || !ember_authority::identity::process_descends_from(
            std::process::id(),
            expected_server.pid,
        )?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential server identity did not match the sealed invocation",
        ));
    }
    Ok(())
}

fn validate_socket(socket: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(socket)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != ember_authority::effective_uid()
        || metadata.mode() & 0o177 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential socket ownership, type, or mode is unsafe",
        ));
    }
    Ok(metadata)
}

fn echo_token(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<()> {
    let mut token = Zeroizing::new(Vec::new());
    reader.take(MAX_TOKEN_BYTES + 1).read_to_end(&mut token)?;
    if token.is_empty() || token.len() as u64 > MAX_TOKEN_BYTES {
        return Err(io::Error::other("invalid credential length"));
    }
    writer.write_all(&token)
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, os::unix::fs::PermissionsExt};

    use super::*;

    const ORIGIN: &str = "https://github.com/owner/repo.git";

    fn current_server_identity() -> ExpectedServerIdentity {
        let pid = std::process::id();
        let pid_version = ember_authority::identity::process_pid_version(pid).unwrap();
        let peer = ember_authority::identity::observed_process(pid, pid_version).unwrap();
        ExpectedServerIdentity {
            pid,
            pid_version,
            executable_digest: peer.executable_digest(),
        }
    }

    fn rejected_socket_token(expected_server: ExpectedServerIdentity) -> Vec<u8> {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let _ = connection.write_all(b"injected-token");
        });
        let mut output = Vec::new();

        assert!(echo_socket_token(&socket, expected_server, &mut output).is_err());
        server.join().unwrap();
        output
    }

    #[test]
    fn server_identity_metadata_requires_every_canonical_value() {
        let digest = "ab".repeat(32);
        let parsed = parse_expected_server_identity(
            Some(OsStr::new("42")),
            Some(OsStr::new("73")),
            Some(OsStr::new(&digest)),
        )
        .unwrap();
        assert_eq!(
            parsed,
            ExpectedServerIdentity {
                pid: 42,
                pid_version: 73,
                executable_digest: ExecutableDigest::from_sha256([0xab_u8; 32]),
            }
        );

        assert!(
            parse_expected_server_identity(
                None,
                Some(OsStr::new("73")),
                Some(OsStr::new(&digest)),
            )
            .is_none()
        );
        assert!(
            parse_expected_server_identity(
                Some(OsStr::new("42")),
                None,
                Some(OsStr::new(&digest)),
            )
            .is_none()
        );
        assert!(
            parse_expected_server_identity(Some(OsStr::new("42")), Some(OsStr::new("73")), None,)
                .is_none()
        );
    }
    #[test]
    fn server_identity_metadata_rejects_malformed_values() {
        let digest = "ab".repeat(32);
        for invalid_pid in ["", "0", "+42", "042", "4294967296", "not-a-pid"] {
            assert!(
                parse_expected_server_identity(
                    Some(OsStr::new(invalid_pid)),
                    Some(OsStr::new("73")),
                    Some(OsStr::new(&digest)),
                )
                .is_none()
            );
        }
        for invalid_version in [
            "",
            "0",
            "+73",
            "073",
            "18446744073709551616",
            "not-a-version",
        ] {
            assert!(
                parse_expected_server_identity(
                    Some(OsStr::new("42")),
                    Some(OsStr::new(invalid_version)),
                    Some(OsStr::new(&digest)),
                )
                .is_none()
            );
        }
        for invalid_digest in ["", "07", "not-a-digest"] {
            assert!(
                parse_expected_server_identity(
                    Some(OsStr::new("42")),
                    Some(OsStr::new("73")),
                    Some(OsStr::new(invalid_digest)),
                )
                .is_none()
            );
        }
        assert!(
            parse_expected_server_identity(
                Some(OsStr::new("42")),
                Some(OsStr::new("73")),
                Some(OsStr::new(&digest.to_uppercase())),
            )
            .is_none()
        );
    }

    #[test]
    fn accepts_only_exact_canonical_github_prompt_origin() {
        assert_eq!(
            response_for_prompt("Username for 'https://github.com/owner/repo.git': ", ORIGIN),
            Some(PromptResponse::Username)
        );
        assert_eq!(
            response_for_prompt(
                "Password for 'https://x-access-token@github.com/owner/repo.git': ",
                ORIGIN,
            ),
            Some(PromptResponse::Password)
        );
        assert_eq!(
            response_for_prompt(
                "Password for 'https://x-access-token@evil.example/owner/repo.git': ",
                ORIGIN,
            ),
            None
        );
        assert_eq!(
            response_for_prompt(
                "Password for 'https://x-access-token@github.com/owner/other.git': ",
                ORIGIN,
            ),
            None
        );
        assert_eq!(
            response_for_prompt(
                "Password for 'https://x-access-token@github.com/owner/repo.git': ",
                "https://github.com/owner/repo.git?redirect=1",
            ),
            None
        );
    }

    #[test]
    fn password_response_echoes_token_exactly() {
        let token = b"github-token-without-a-trailing-newline";
        let mut output = Vec::new();

        echo_token(&mut Cursor::new(token), &mut output).unwrap();

        assert_eq!(output, token);
    }

    #[test]
    fn rejects_empty_or_oversized_credentials_without_output() {
        let mut empty_output = Vec::new();
        assert!(echo_token(&mut Cursor::new(Vec::<u8>::new()), &mut empty_output).is_err());
        assert!(empty_output.is_empty());

        let mut oversized_output = Vec::new();
        let oversized = vec![b'x'; MAX_TOKEN_BYTES as usize + 1];
        assert!(echo_token(&mut Cursor::new(oversized), &mut oversized_output).is_err());
        assert!(oversized_output.is_empty());
    }

    #[test]
    fn reads_token_after_sealed_socket_validation() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection.write_all(b"socket-token").unwrap();
        });
        let mut output = Vec::new();

        let expected_server = current_server_identity();
        echo_socket_token_with(&socket, expected_server, &mut output, |_, identity| {
            assert_eq!(identity, expected_server);
            Ok(())
        })
        .unwrap();
        server.join().unwrap();

        assert_eq!(output, b"socket-token");
    }

    #[test]
    fn rejects_unsafe_socket_mode_before_connecting() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let mut output = Vec::new();

        assert!(echo_socket_token(&socket, current_server_identity(), &mut output).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_non_socket_credential_path() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        fs::write(&socket, b"not a socket").unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let mut output = Vec::new();

        assert!(echo_socket_token(&socket, current_server_identity(), &mut output).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_same_pid_with_mismatched_process_instance_before_reading_token() {
        let mut expected_server = current_server_identity();
        expected_server.pid_version = if expected_server.pid_version == u64::MAX {
            u64::MAX - 1
        } else {
            expected_server.pid_version + 1
        };

        assert!(rejected_socket_token(expected_server).is_empty());
    }

    #[test]
    fn rejects_same_uid_server_with_mismatched_executable_before_reading_token() {
        let mut expected_server = current_server_identity();
        let mismatched =
            if expected_server.executable_digest == ExecutableDigest::from_sha256([0_u8; 32]) {
                [1_u8; 32]
            } else {
                [0_u8; 32]
            };
        expected_server.executable_digest = ExecutableDigest::from_sha256(mismatched);

        assert!(rejected_socket_token(expected_server).is_empty());
    }
}
