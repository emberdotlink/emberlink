use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        net::UnixListener,
        process::ExitStatusExt,
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use command_fds::{CommandFdExt, FdMapping};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(not(target_os = "macos"))]
use std::os::fd::OwnedFd;

use crate::{
    artifact::VerifiedArtifact,
    effective_uid, identity,
    model::{GitRefPublicationInput, ProcessOutcome},
    principal::ExecutableDigest,
    provider::MintedCredential,
    same_file_version,
};

const GIT_EXECUTABLE_FD: i32 = 7;
const CREDENTIAL_SOCKET_ENV: &str = "EMBER_ASKPASS_SOCKET";
const CREDENTIAL_ORIGIN_ENV: &str = "EMBER_ASKPASS_ORIGIN";
const CREDENTIAL_SERVER_PID_ENV: &str = "EMBER_ASKPASS_SERVER_PID";
const CREDENTIAL_SERVER_PID_VERSION_ENV: &str = "EMBER_ASKPASS_SERVER_PID_VERSION";
const CREDENTIAL_SERVER_EXECUTABLE_DIGEST_ENV: &str =
    "EMBER_ASKPASS_SERVER_EXECUTABLE_DIGEST_SHA256";
const MAX_CREDENTIAL_REQUESTS: usize = 4;
const MAX_REJECTED_CREDENTIAL_ATTEMPTS: usize = 4;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const OUTPUT_LIMIT: u64 = 64 * 1024;
const EMPTY_CONFIG: &str = "/dev/null";

/// An absolute executable path paired with the digest approved by the daemon operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedExecutable {
    path: PathBuf,
    digest_sha256: [u8; 32],
}

impl ReviewedExecutable {
    pub fn new(path: impl Into<PathBuf>, digest_sha256: [u8; 32]) -> Result<Self, GitRunnerError> {
        let path = path.into();
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(GitRunnerError::ExecutablePathNotAbsolute(path));
        }
        Ok(Self {
            path,
            digest_sha256,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest_sha256)
    }

    pub(crate) fn open_verified(&self) -> Result<VerifiedExecutable, GitRunnerError> {
        validate_executable_ancestry(&self.path)?;
        let before =
            fs::symlink_metadata(&self.path).map_err(|source| GitRunnerError::ExecutableIo {
                path: self.path.clone(),
                source,
            })?;
        validate_executable_metadata(&self.path, &before)?;

        let mut executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.path.clone(),
                source,
            })?;
        let opened = executable
            .metadata()
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.path.clone(),
                source,
            })?;
        validate_executable_metadata(&self.path, &opened)?;
        if !same_inode(&before, &opened) {
            return Err(GitRunnerError::ExecutableChanged(self.path.clone()));
        }

        let actual = sha256(&mut executable).map_err(|source| GitRunnerError::ExecutableIo {
            path: self.path.clone(),
            source,
        })?;
        let after = executable
            .metadata()
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.path.clone(),
                source,
            })?;
        validate_executable_metadata(&self.path, &after)?;
        if !same_file_version(&opened, &after) {
            return Err(GitRunnerError::ExecutableChanged(self.path.clone()));
        }
        if actual != self.digest_sha256 {
            return Err(GitRunnerError::ExecutableDigestMismatch {
                path: self.path.clone(),
                expected: hex::encode(self.digest_sha256),
                actual: hex::encode(actual),
            });
        }
        executable
            .seek(SeekFrom::Start(0))
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.path.clone(),
                source,
            })?;
        Ok(VerifiedExecutable {
            file: executable,
            source_path: self.path.clone(),
            #[cfg(test)]
            dev: opened.dev(),
            #[cfg(test)]
            ino: opened.ino(),
        })
    }
    #[cfg(test)]
    fn reverify(&self) -> Result<(), GitRunnerError> {
        self.open_verified().map(drop)
    }
}

pub(crate) struct VerifiedExecutable {
    file: File,
    source_path: PathBuf,
    #[cfg(test)]
    dev: u64,
    #[cfg(test)]
    ino: u64,
}

pub(crate) struct ExecutableTarget {
    path: PathBuf,
    mappings: Vec<FdMapping>,
    _directory: Option<tempfile::TempDir>,
    _anchor: Option<File>,
}

impl ExecutableTarget {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn take_mappings(&mut self) -> Vec<FdMapping> {
        std::mem::take(&mut self.mappings)
    }
}

impl VerifiedExecutable {
    pub(crate) fn execution_target(
        self,
        _child_fd: i32,
    ) -> Result<ExecutableTarget, GitRunnerError> {
        #[cfg(target_os = "macos")]
        {
            let opened = self
                .file
                .metadata()
                .map_err(|source| GitRunnerError::ExecutableIo {
                    path: self.source_path.clone(),
                    source,
                })?;
            if immutable_source_path(&self.source_path, &opened) {
                let current = fs::symlink_metadata(&self.source_path).map_err(|source| {
                    GitRunnerError::ExecutableIo {
                        path: self.source_path.clone(),
                        source,
                    }
                })?;
                validate_executable_metadata(&self.source_path, &current)?;
                if !same_file_version(&opened, &current) {
                    return Err(GitRunnerError::ExecutableChanged(self.source_path.clone()));
                }
                return Ok(ExecutableTarget {
                    path: self.source_path.clone(),
                    mappings: Vec::new(),
                    _directory: None,
                    _anchor: Some(self.file),
                });
            }

            self.materialized_execution_target()
        }
        #[cfg(not(target_os = "macos"))]
        {
            let parent_fd: OwnedFd = self.file.into();
            Ok(ExecutableTarget {
                path: executable_fd_path(_child_fd),
                mappings: vec![FdMapping {
                    parent_fd,
                    child_fd: _child_fd,
                }],
                _directory: None,
                _anchor: None,
            })
        }
    }

    fn materialized_execution_target(mut self) -> Result<ExecutableTarget, GitRunnerError> {
        let directory = tempfile::Builder::new()
            .prefix("ember-exec-")
            .tempdir()
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.source_path.clone(),
                source,
            })?;
        set_private_directory(directory.path()).map_err(|error| match error {
            GitRunnerError::WorkspaceIo(source) => GitRunnerError::ExecutableIo {
                path: self.source_path.clone(),
                source,
            },
            other => other,
        })?;
        let path = directory.path().join("executable");
        let mut materialized = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o500)
            .open(&path)
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.source_path.clone(),
                source,
            })?;
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| io::copy(&mut self.file, &mut materialized))
            .and_then(|_| materialized.sync_all())
            .map_err(|source| GitRunnerError::ExecutableIo {
                path: self.source_path.clone(),
                source,
            })?;
        Ok(ExecutableTarget {
            path,
            mappings: Vec::new(),
            _directory: Some(directory),
            _anchor: None,
        })
    }

    #[cfg(test)]
    fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn executable_fd_path(child_fd: i32) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from(format!("/proc/self/fd/{child_fd}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        PathBuf::from(format!("/dev/fd/{child_fd}"))
    }
}

fn validate_executable_ancestry(path: &Path) -> Result<(), GitRunnerError> {
    let euid = effective_uid();
    let mut parent = path
        .parent()
        .ok_or_else(|| GitRunnerError::ExecutableUnsafePath(path.to_owned()))?;
    loop {
        let metadata =
            fs::symlink_metadata(parent).map_err(|source| GitRunnerError::ExecutableIo {
                path: parent.to_owned(),
                source,
            })?;
        if !metadata.file_type().is_dir()
            || !safe_owner(&metadata, euid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(GitRunnerError::ExecutableUnsafePath(parent.to_owned()));
        }
        match parent.parent() {
            Some(next) => parent = next,
            None => break,
        }
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn immutable_source_path(path: &Path, opened: &fs::Metadata) -> bool {
    opened.uid() == 0 && root_owned_safe_ancestry(path)
}
#[cfg(target_os = "macos")]
fn root_owned_safe_ancestry(path: &Path) -> bool {
    let Some(mut parent) = path.parent() else {
        return false;
    };
    loop {
        let Ok(metadata) = fs::symlink_metadata(parent) else {
            return false;
        };
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return false;
        }
        match parent.parent() {
            Some(next) => parent = next,
            None => return true,
        }
    }
}

fn validate_executable_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), GitRunnerError> {
    if metadata.file_type().is_symlink() {
        return Err(GitRunnerError::ExecutableSymlink(path.to_owned()));
    }
    if !metadata.file_type().is_file() {
        return Err(GitRunnerError::ExecutableNotFile(path.to_owned()));
    }
    if !safe_owner(metadata, effective_uid())
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(GitRunnerError::ExecutableUnsafePath(path.to_owned()));
    }
    Ok(())
}

pub(crate) fn safe_owner(metadata: &fs::Metadata, euid: u32) -> bool {
    metadata.uid() == 0 || metadata.uid() == euid
}

fn same_inode(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[derive(Clone, Debug)]
pub struct GitRunner {
    git: ReviewedExecutable,
    askpass: ReviewedExecutable,
    #[cfg(test)]
    credential_peer_fingerprint: fn(&Path) -> io::Result<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitRunResult {
    pub executable_digest_sha256: String,
    pub credential_helper_digest_sha256: String,
    pub artifact_digest_sha256: String,
    pub credential_peer_served_count: usize,
    pub credential_peer_rejected_count: usize,
    pub process: ProcessOutcome,
}

impl GitRunner {
    pub fn new(git: ReviewedExecutable, askpass: ReviewedExecutable) -> Self {
        Self {
            git,
            askpass,
            #[cfg(test)]
            credential_peer_fingerprint: identity::reviewed_executable_fingerprint,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_credential_peer_fingerprint_for_test(
        mut self,
        fingerprint: fn(&Path) -> io::Result<[u8; 32]>,
    ) -> Self {
        self.credential_peer_fingerprint = fingerprint;
        self
    }

    pub fn executable_digest_hex(&self) -> String {
        self.git.digest_hex()
    }

    pub fn credential_helper_digest_hex(&self) -> String {
        self.askpass.digest_hex()
    }

    fn expected_credential_peer_digest(
        &self,
        path: &Path,
    ) -> Result<ExecutableDigest, GitRunnerError> {
        #[cfg(test)]
        {
            credential_peer_digest_with(path, self.credential_peer_fingerprint)
        }
        #[cfg(not(test))]
        {
            credential_peer_digest(path)
        }
    }

    /// Publishes exactly the object and destination authorized by `input`.
    ///
    /// The artifact is a verified, pathless store handle. The credential is borrowed only long
    /// enough to serve it over the private, process-bound askpass socket.
    pub fn publish(
        &self,
        input: &GitRefPublicationInput,
        artifact: VerifiedArtifact,
        credential: &MintedCredential,
    ) -> Result<GitRunResult, GitRunnerError> {
        self.publish_with_token(input, artifact, credential.token())
    }

    fn publish_with_token(
        &self,
        input: &GitRefPublicationInput,
        mut artifact: VerifiedArtifact,
        token: &str,
    ) -> Result<GitRunResult, GitRunnerError> {
        if input.new_oid.is_zero() {
            return Err(GitRunnerError::ZeroNewOid);
        }
        if input.new_oid.as_str().len() != input.expected_old_oid.as_str().len() {
            return Err(GitRunnerError::OidFormatMismatch);
        }
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(GitRunnerError::InvalidCredentialLength);
        }
        if artifact.artifact_ref() != &input.artifact {
            return Err(GitRunnerError::ArtifactReferenceMismatch);
        }

        let private = tempfile::Builder::new()
            .prefix("ember-git-")
            .tempdir()
            .map_err(GitRunnerError::WorkspaceIo)?;
        set_private_directory(private.path())?;
        let home = private.path().join("home");
        let repository = private.path().join("repository.git");
        fs::create_dir(&home).map_err(GitRunnerError::WorkspaceIo)?;
        set_private_directory(&home)?;
        fs::create_dir(&repository).map_err(GitRunnerError::WorkspaceIo)?;
        set_private_directory(&repository)?;

        let bundle_path = private.path().join("artifact.bundle");
        let mut bundle = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&bundle_path)
            .map_err(GitRunnerError::WorkspaceIo)?;
        artifact
            .seek(SeekFrom::Start(0))
            .map_err(GitRunnerError::ArtifactRead)?;
        io::copy(&mut artifact, &mut bundle).map_err(GitRunnerError::ArtifactRead)?;
        bundle.sync_all().map_err(GitRunnerError::WorkspaceIo)?;
        drop(bundle);

        let object_format = if input.new_oid.as_str().len() == 40 {
            "--object-format=sha1"
        } else {
            "--object-format=sha256"
        };
        self.require_success(
            "init",
            self.run_git(&repository, &["init", "--bare", object_format, "."], None)?
                .process,
        )?;

        let bundle_arg = path_argument(&bundle_path)?;
        self.require_success(
            "bundle-verify",
            self.run_git(&repository, &["bundle", "verify", bundle_arg], None)?
                .process,
        )?;
        self.require_success(
            "bundle-import",
            self.run_git(&repository, &["bundle", "unbundle", bundle_arg], None)?
                .process,
        )?;
        fs::remove_file(&bundle_path).map_err(GitRunnerError::WorkspaceIo)?;

        let object_expression = format!("{}^{{object}}", input.new_oid.as_str());
        self.require_success(
            "object-proof",
            self.run_git(
                &repository,
                &["cat-file", "-e", object_expression.as_str()],
                None,
            )?
            .process,
        )?;

        let endpoint = format!(
            "https://github.com/{}/{}.git",
            input.repository.owner(),
            input.repository.repository()
        );
        let refspec = format!(
            "{}:{}",
            input.new_oid.as_str(),
            input.destination_ref.as_str()
        );
        let lease = format!(
            "--force-with-lease={}:{}",
            input.destination_ref.as_str(),
            input.expected_old_oid.as_str()
        );
        let run = self.run_git(
            &repository,
            &["push", lease.as_str(), endpoint.as_str(), refspec.as_str()],
            Some(CredentialRequest {
                secret: token,
                expected_origin: &endpoint,
            }),
        )?;

        Ok(GitRunResult {
            executable_digest_sha256: self.git.digest_hex(),
            credential_helper_digest_sha256: self.askpass.digest_hex(),
            artifact_digest_sha256: input.artifact.digest_hex().to_owned(),
            credential_peer_served_count: run.credentials.served,
            credential_peer_rejected_count: run.credentials.rejected,
            process: run.process,
        })
    }

    fn require_success(
        &self,
        stage: &'static str,
        outcome: ProcessOutcome,
    ) -> Result<(), GitRunnerError> {
        if outcome.exit_code == Some(0) {
            Ok(())
        } else {
            Err(GitRunnerError::GitPreparationFailed { stage, outcome })
        }
    }

    fn run_git(
        &self,
        repository: &Path,
        arguments: &[&str],
        credential: Option<CredentialRequest<'_>>,
    ) -> Result<GitCommandResult, GitRunnerError> {
        let mut git_target = self
            .git
            .open_verified()?
            .execution_target(GIT_EXECUTABLE_FD)?;
        let fd_mappings = git_target.take_mappings();

        let home = repository
            .parent()
            .expect("runner repository always has a private parent")
            .join("home");
        let mut command = Command::new(git_target.path());
        command
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", EMPTY_CONFIG)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GCM_INTERACTIVE", "never")
            .env("LC_ALL", "C")
            .current_dir(repository)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "credential.helper=",
                "-c",
                "http.proxy=",
                "-c",
                "https.proxy=",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "http.followRedirects=false",
                "-c",
                "credential.useHttpPath=true",
            ])
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut askpass_target = None;
        let mut credential_server = None;
        if let Some(credential) = credential {
            let target = self
                .askpass
                .open_verified()?
                .materialized_execution_target()?;
            let expected_peer_digest = self.expected_credential_peer_digest(target.path())?;
            let server_pid = std::process::id();
            let server_pid_version = identity::process_pid_version(server_pid)
                .map_err(GitRunnerError::CredentialChannel)?;
            let server_identity = identity::observed_process(server_pid, server_pid_version)
                .map_err(GitRunnerError::CredentialChannel)?;
            let socket_path = repository
                .parent()
                .expect("runner repository always has a private parent")
                .join("credential.sock");
            let listener =
                UnixListener::bind(&socket_path).map_err(GitRunnerError::CredentialChannel)?;
            set_private_socket(&socket_path)?;
            let expected_uid = fs::symlink_metadata(&socket_path)
                .map_err(GitRunnerError::CredentialChannel)?
                .uid();
            listener
                .set_nonblocking(true)
                .map_err(GitRunnerError::CredentialChannel)?;
            command
                .env("GIT_ASKPASS", target.path())
                .env("SSH_ASKPASS", target.path())
                .env(CREDENTIAL_SOCKET_ENV, &socket_path)
                .env(CREDENTIAL_ORIGIN_ENV, credential.expected_origin)
                .env(CREDENTIAL_SERVER_PID_ENV, server_pid.to_string())
                .env(
                    CREDENTIAL_SERVER_PID_VERSION_ENV,
                    server_pid_version.to_string(),
                )
                .env(
                    CREDENTIAL_SERVER_EXECUTABLE_DIGEST_ENV,
                    server_identity.executable_digest().to_sha256_hex(),
                );
            askpass_target = Some(target);
            credential_server = Some((
                listener,
                credential.secret,
                expected_uid,
                expected_peer_digest,
            ));
        }
        command
            .fd_mappings(fd_mappings)
            .map_err(|_| GitRunnerError::ExecutableFdCollision)?;

        let _askpass_target = askpass_target;
        let mut child = command.spawn().map_err(GitRunnerError::GitSpawn)?;
        let git_pid = child.id();
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_child(&mut child);
                return Err(GitRunnerError::MissingProcessPipe);
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                terminate_child(&mut child);
                return Err(GitRunnerError::MissingProcessPipe);
            }
        };
        let stdout_thread = thread::spawn(move || digest_bounded(stdout));
        let stderr_thread = thread::spawn(move || digest_bounded(stderr));
        let credential_stop = AtomicBool::new(false);
        let (status, credential_result) = thread::scope(|scope| {
            let credential_thread =
                credential_server.map(|(listener, secret, expected_uid, expected_digest)| {
                    let stop = &credential_stop;
                    scope.spawn(move || {
                        serve_credentials(
                            listener,
                            secret,
                            git_pid,
                            expected_uid,
                            expected_digest,
                            stop,
                        )
                    })
                });
            let status = child.wait();
            credential_stop.store(true, Ordering::Release);
            let credential_result = match credential_thread {
                Some(thread) => thread
                    .join()
                    .map_err(|_| GitRunnerError::CredentialServerPanicked)
                    .and_then(|result| result),
                None => Ok(CredentialChannelEvidence::default()),
            };
            (status, credential_result)
        });
        let credentials = credential_result?;
        let status = match status {
            Ok(status) => status,
            Err(source) => {
                terminate_child(&mut child);
                return Err(GitRunnerError::GitWait(source));
            }
        };
        let stdout_digest = join_digest(stdout_thread)?;
        let stderr_digest = join_digest(stderr_thread)?;

        Ok(GitCommandResult {
            process: process_outcome(status, stdout_digest, stderr_digest),
            credentials,
        })
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn set_private_directory(path: &Path) -> Result<(), GitRunnerError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(GitRunnerError::WorkspaceIo)
}

fn path_argument(path: &Path) -> Result<&str, GitRunnerError> {
    path.to_str().ok_or(GitRunnerError::NonUtf8PrivatePath)
}

fn set_private_socket(path: &Path) -> Result<(), GitRunnerError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(GitRunnerError::CredentialChannel)
}

fn credential_peer_digest(path: &Path) -> Result<ExecutableDigest, GitRunnerError> {
    credential_peer_digest_with(path, identity::reviewed_executable_fingerprint)
}

fn credential_peer_digest_with(
    path: &Path,
    fingerprint: fn(&Path) -> io::Result<[u8; 32]>,
) -> Result<ExecutableDigest, GitRunnerError> {
    fingerprint(path)
        .map(ExecutableDigest::from_sha256)
        .map_err(|source| GitRunnerError::ExecutableIo {
            path: path.to_owned(),
            source,
        })
}

struct CredentialRequest<'a> {
    secret: &'a str,
    expected_origin: &'a str,
}

struct GitCommandResult {
    process: ProcessOutcome,
    credentials: CredentialChannelEvidence,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CredentialChannelEvidence {
    served: usize,
    rejected: usize,
}

fn serve_credentials(
    listener: UnixListener,
    secret: &str,
    git_pid: u32,
    expected_uid: u32,
    expected_digest: ExecutableDigest,
    stop: &AtomicBool,
) -> Result<CredentialChannelEvidence, GitRunnerError> {
    let mut evidence = CredentialChannelEvidence::default();
    while !stop.load(Ordering::Acquire) && evidence.served < MAX_CREDENTIAL_REQUESTS {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(error) => return Err(GitRunnerError::CredentialChannel(error)),
        };
        let accepted = identity::peer_identity(&stream).is_ok_and(|peer| {
            peer.euid() == expected_uid
                && peer.executable_digest() == expected_digest
                && identity::process_descends_from(peer.pid(), git_pid).unwrap_or(false)
        });
        if !accepted {
            evidence.rejected += 1;
            if evidence.rejected >= MAX_REJECTED_CREDENTIAL_ATTEMPTS {
                return Err(GitRunnerError::CredentialPeerRejectionLimit {
                    rejected: evidence.rejected,
                });
            }
            continue;
        }
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(GitRunnerError::CredentialChannel)?;
        stream
            .write_all(secret.as_bytes())
            .map_err(GitRunnerError::CredentialChannel)?;
        evidence.served += 1;
    }
    Ok(evidence)
}

fn sha256(mut reader: impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

fn digest_bounded(mut reader: impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut remaining = OUTPUT_LIMIT;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let captured = usize::try_from(remaining.min(read as u64))
            .expect("captured output length fits in usize");
        hasher.update(&buffer[..captured]);
        remaining -= captured as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn join_digest(thread: thread::JoinHandle<io::Result<String>>) -> Result<String, GitRunnerError> {
    thread
        .join()
        .map_err(|_| GitRunnerError::OutputReaderPanicked)?
        .map_err(GitRunnerError::OutputRead)
}

fn process_outcome(
    status: ExitStatus,
    stdout_digest: String,
    stderr_digest: String,
) -> ProcessOutcome {
    ProcessOutcome {
        exit_code: status.code(),
        signal: status.signal(),
        stdout_digest: Some(stdout_digest),
        stderr_digest: Some(stderr_digest),
    }
}

#[derive(Debug, Error)]
pub enum GitRunnerError {
    #[error("reviewed executable path is not absolute: {0}")]
    ExecutablePathNotAbsolute(PathBuf),
    #[error("reviewed executable is not a regular file: {0}")]
    ExecutableNotFile(PathBuf),
    #[error("reviewed executable may not be a symbolic link: {0}")]
    ExecutableSymlink(PathBuf),
    #[error("reviewed executable has unsafe ownership, mode, or ancestry: {0}")]
    ExecutableUnsafePath(PathBuf),
    #[error("reviewed executable changed while it was being opened: {0}")]
    ExecutableChanged(PathBuf),
    #[error("could not read reviewed executable {path}: {source}")]
    ExecutableIo { path: PathBuf, source: io::Error },
    #[error("reviewed executable digest mismatch for {path}: expected {expected}, got {actual}")]
    ExecutableDigestMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("new Git object ID may not be zero")]
    ZeroNewOid,
    #[error("old and new Git object IDs use different hash formats")]
    OidFormatMismatch,
    #[error("credential length is invalid")]
    InvalidCredentialLength,
    #[error("verified artifact does not match the publication input")]
    ArtifactReferenceMismatch,
    #[error("could not read verified artifact: {0}")]
    ArtifactRead(io::Error),
    #[error("could not create private Git workspace: {0}")]
    WorkspaceIo(io::Error),
    #[error("private Git workspace path is not UTF-8")]
    NonUtf8PrivatePath,
    #[error("credential channel failed: {0}")]
    CredentialChannel(io::Error),
    #[error("credential server panicked")]
    CredentialServerPanicked,
    #[error("credential peer rejection limit reached after {rejected} attempts")]
    CredentialPeerRejectionLimit { rejected: usize },
    #[error("reviewed executable file descriptor mapping collided")]
    ExecutableFdCollision,
    #[error("could not spawn reviewed Git executable: {0}")]
    GitSpawn(io::Error),
    #[error("could not wait for reviewed Git executable: {0}")]
    GitWait(io::Error),
    #[error("Git process did not expose its output pipes")]
    MissingProcessPipe,
    #[error("could not read bounded Git output: {0}")]
    OutputRead(io::Error),
    #[error("Git output reader panicked")]
    OutputReaderPanicked,
    #[error("Git preparation stage {stage} failed")]
    GitPreparationFailed {
        stage: &'static str,
        outcome: ProcessOutcome,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        fs,
        io::Cursor,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        str::FromStr,
    };

    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        artifact::ArtifactStore,
        model::{ArtifactRef, GitOid, GitRef, RepositoryResource},
    };

    const TOKEN: &str = "installation-token-that-must-never-be-recorded";
    const FAKE_GIT: &str = r#"#!/bin/sh
observed='@OBSERVED@'
{
  printf '%s' 'ARGV'
  for argument in "$@"; do printf ' <%s>' "$argument"; done
  printf '\nENV\n'
  /usr/bin/env
  printf '%s\n' 'END'
} >> "$observed"
operation=
for argument in "$@"; do
  if [ "$argument" = push ]; then operation=push; fi
done
if [ "$operation" = push ]; then
  [ -x "$GIT_ASKPASS" ] || exit 80
  [ -S "$EMBER_ASKPASS_SOCKET" ] || exit 81
fi
printf '%s\n' 'bounded stdout'
printf '%s\n' 'bounded stderr' >&2
exit 0
"#;
    const LARGE_OUTPUT_FAKE_GIT: &str = r#"#!/bin/sh
printf '%65536s' ''
printf 'overflow'
exit 0
"#;
    const FAKE_ASKPASS: &str = "#!/bin/sh\nexit 2\n";

    fn test_dir() -> TempDir {
        tempfile::Builder::new()
            .prefix("git-runner-")
            .tempdir_in(std::env::current_dir().expect("current directory"))
            .expect("create safe test directory")
    }

    struct Fixture {
        root: TempDir,
        store_root: PathBuf,
        workspace: PathBuf,
        runner: GitRunner,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_git_source(FAKE_GIT)
        }

        fn with_git_source(source: &str) -> Self {
            let root = test_dir();
            let observed = root.path().join("observed");
            let git_source = source.replace(
                "@OBSERVED@",
                observed.to_str().expect("UTF-8 test observation path"),
            );
            let git = write_executable(root.path().join("fake-git"), &git_source);
            let askpass = write_executable(root.path().join("fake-askpass"), FAKE_ASKPASS);
            let store_root = root.path().join("artifact-store");
            let workspace = root.path().join("caller-workspace");
            fs::create_dir(&workspace).unwrap();
            fs::write(workspace.join("sentinel"), b"caller-owned").unwrap();
            let runner = GitRunner::new(reviewed(git), reviewed(askpass))
                .with_credential_peer_fingerprint_for_test(test_fixture_peer_fingerprint);
            Self {
                root,
                store_root,
                workspace,
                runner,
            }
        }

        fn verified_artifact(&self) -> (ArtifactRef, VerifiedArtifact) {
            let store = ArtifactStore::new(&self.store_root, 1024 * 1024).unwrap();
            let reference = store.import(Cursor::new(b"fake bundle bytes")).unwrap();
            let verified = store.open_verified(&reference).unwrap();
            (reference, verified)
        }

        fn observed(&self) -> String {
            fs::read_to_string(self.root.path().join("observed")).unwrap()
        }
    }

    fn write_executable(path: PathBuf, contents: &str) -> PathBuf {
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn reviewed(path: PathBuf) -> ReviewedExecutable {
        let digest: [u8; 32] = Sha256::digest(fs::read(&path).unwrap()).into();
        ReviewedExecutable::new(path, digest).unwrap()
    }

    fn test_fixture_peer_fingerprint(_path: &Path) -> io::Result<[u8; 32]> {
        Ok([0_u8; 32])
    }

    fn input(artifact: ArtifactRef, new_oid: &str) -> GitRefPublicationInput {
        GitRefPublicationInput {
            repository: RepositoryResource::from_str("github:Owner/Repo").unwrap(),
            artifact,
            expected_old_oid: GitOid::from_str("1111111111111111111111111111111111111111").unwrap(),
            new_oid: GitOid::from_str(new_oid).unwrap(),
            destination_ref: GitRef::from_str("refs/heads/release").unwrap(),
        }
    }

    #[test]
    fn rejects_executable_hash_mismatch() {
        let fixture = Fixture::new();
        let (artifact_ref, artifact) = fixture.verified_artifact();
        fs::write(fixture.runner.git.path(), b"reviewed file was replaced").unwrap();

        let error = fixture
            .runner
            .publish_with_token(
                &input(artifact_ref, "2222222222222222222222222222222222222222"),
                artifact,
                TOKEN,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            GitRunnerError::ExecutableDigestMismatch { .. }
        ));
    }

    #[test]
    fn rejects_reviewed_executable_symlink() {
        let root = test_dir();
        let target = write_executable(root.path().join("git-target"), FAKE_GIT);
        let link = root.path().join("git-link");
        symlink(&target, &link).unwrap();
        let digest: [u8; 32] = Sha256::digest(fs::read(&target).unwrap()).into();
        let reviewed = ReviewedExecutable::new(link, digest).unwrap();

        let error = reviewed.reverify().unwrap_err();

        assert!(matches!(error, GitRunnerError::ExecutableSymlink(_)));
    }

    #[test]
    fn rejects_group_writable_executable_ancestry() {
        let root = test_dir();
        let executable = write_executable(root.path().join("git"), "#!/bin/sh\nexit 0\n");
        let reviewed = reviewed(executable);
        let original = fs::metadata(root.path()).unwrap().permissions();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o770)).unwrap();

        let error = reviewed.reverify().unwrap_err();

        fs::set_permissions(root.path(), original).unwrap();
        assert!(matches!(error, GitRunnerError::ExecutableUnsafePath(_)));
    }

    #[test]
    fn swapped_path_is_refused_as_execution_target() {
        const EXEC_FD: i32 = 42;
        let root = test_dir();
        let path = write_executable(
            root.path().join("reviewed"),
            "#!/bin/sh\nprintf reviewed-inode\n",
        );
        let reviewed = reviewed(path.clone());
        let verified = reviewed.open_verified().unwrap();
        let verified_identity = verified.identity();
        let displaced = root.path().join("displaced");
        fs::rename(&path, &displaced).unwrap();
        write_executable(path.clone(), "#!/bin/sh\nprintf replacement-path\n");
        let replacement = fs::metadata(&path).unwrap();
        assert_ne!(verified_identity, (replacement.dev(), replacement.ino()));

        let mut target = verified.execution_target(EXEC_FD).unwrap();
        let mut command = Command::new(target.path());
        command.fd_mappings(target.take_mappings()).unwrap();
        let output = command.output().unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"reviewed-inode");
        assert!(matches!(
            reviewed.reverify(),
            Err(GitRunnerError::ExecutableDigestMismatch { .. })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn root_owned_platform_executable_runs_from_immutable_source_path() {
        let path = PathBuf::from("/usr/bin/true");
        let digest: [u8; 32] = Sha256::digest(fs::read(&path).unwrap()).into();
        let reviewed = ReviewedExecutable::new(path.clone(), digest).unwrap();

        let target = reviewed
            .open_verified()
            .unwrap()
            .execution_target(42)
            .unwrap();
        let output = Command::new(target.path()).output().unwrap();

        assert_eq!(target.path(), path);
        assert!(output.status.success());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn executable_beneath_non_root_ancestor_is_materialized_from_reviewed_descriptor() {
        let root = test_dir();
        let path = write_executable(
            root.path().join("reviewed"),
            "#!/bin/sh\nprintf reviewed-materialization\n",
        );
        assert!(!root_owned_safe_ancestry(&path));
        let root_owned = fs::metadata("/usr/bin/true").unwrap();
        assert_eq!(root_owned.uid(), 0);
        assert!(!immutable_source_path(&path, &root_owned));
        let source_identity = {
            let metadata = fs::metadata(&path).unwrap();
            (metadata.dev(), metadata.ino())
        };

        let target = reviewed(path.clone())
            .open_verified()
            .unwrap()
            .execution_target(42)
            .unwrap();
        let target_metadata = fs::metadata(target.path()).unwrap();

        assert_ne!(target.path(), path);
        assert_ne!(
            source_identity,
            (target_metadata.dev(), target_metadata.ino())
        );
        assert_eq!(
            Command::new(target.path()).output().unwrap().stdout,
            b"reviewed-materialization"
        );
    }

    #[test]
    fn rejects_askpass_hash_mismatch_before_push() {
        let fixture = Fixture::new();
        let (artifact_ref, artifact) = fixture.verified_artifact();
        fs::write(
            fixture.runner.askpass.path(),
            b"reviewed askpass was replaced",
        )
        .unwrap();

        let error = fixture
            .runner
            .publish_with_token(
                &input(artifact_ref, "2222222222222222222222222222222222222222"),
                artifact,
                TOKEN,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            GitRunnerError::ExecutableDigestMismatch { .. }
        ));
        assert!(!fixture.observed().contains("<push>"));
    }

    #[test]
    fn credential_server_wiring_uses_the_peer_identity_fingerprint_namespace() {
        let source = std::env::current_exe().unwrap();
        let reviewed = reviewed(source);
        #[cfg(target_os = "macos")]
        let content_digest = ExecutableDigest::from_sha256(reviewed.digest_sha256);
        let target = reviewed
            .open_verified()
            .unwrap()
            .materialized_execution_target()
            .unwrap();

        let expected_peer = credential_peer_digest(target.path()).unwrap();
        let independently_measured = ExecutableDigest::from_sha256(
            identity::reviewed_executable_fingerprint(target.path()).unwrap(),
        );

        assert_eq!(expected_peer, independently_measured);
        #[cfg(target_os = "macos")]
        assert_ne!(expected_peer, content_digest);
    }

    #[test]
    fn rejects_zero_new_oid_before_executing_git() {
        let fixture = Fixture::new();
        let (artifact_ref, artifact) = fixture.verified_artifact();

        let error = fixture
            .runner
            .publish_with_token(
                &input(artifact_ref, "0000000000000000000000000000000000000000"),
                artifact,
                TOKEN,
            )
            .unwrap_err();

        assert!(matches!(error, GitRunnerError::ZeroNewOid));
        assert!(!fixture.root.path().join("observed").exists());
    }

    #[test]
    fn uses_fixed_endpoint_exact_refspec_and_clean_environment_without_leaking_token() {
        let fixture = Fixture::new();
        let (artifact_ref, artifact) = fixture.verified_artifact();
        let new_oid = "2222222222222222222222222222222222222222";
        let server_pid = std::process::id();
        let server_pid_version = identity::process_pid_version(server_pid).unwrap();
        let server_identity = identity::observed_process(server_pid, server_pid_version).unwrap();
        let expected_server_pid = format!("{CREDENTIAL_SERVER_PID_ENV}={server_pid}");
        let expected_server_pid_version =
            format!("{CREDENTIAL_SERVER_PID_VERSION_ENV}={server_pid_version}");
        let expected_server_digest = format!(
            "{CREDENTIAL_SERVER_EXECUTABLE_DIGEST_ENV}={}",
            server_identity.executable_digest().to_sha256_hex()
        );

        let result = fixture
            .runner
            .publish_with_token(&input(artifact_ref, new_oid), artifact, TOKEN)
            .unwrap();

        assert_eq!(result.process.exit_code, Some(0));
        let observed = fixture.observed();
        let push = observed
            .split("ARGV")
            .find(|record| record.contains("<push>"))
            .unwrap();
        let expected_push = format!(
            "<push> <--force-with-lease=refs/heads/release:1111111111111111111111111111111111111111> <https://github.com/owner/repo.git> <{new_oid}:refs/heads/release>\nENV"
        );
        assert!(push.contains(&expected_push));
        assert!(observed.contains("<bundle> <verify>"));
        assert!(observed.contains("<bundle> <unbundle>"));
        assert!(observed.contains("<init> <--bare> <--object-format=sha1> <.>"));
        assert!(observed.contains(&format!("<cat-file> <-e> <{new_oid}^{{object}}>")));
        assert!(observed.contains("GIT_TERMINAL_PROMPT=0"));
        assert!(observed.contains("GIT_CONFIG_NOSYSTEM=1"));
        assert!(observed.contains("<-c> <http.followRedirects=false>"));
        assert!(observed.contains("<-c> <credential.useHttpPath=true>"));
        assert!(observed.contains("EMBER_ASKPASS_ORIGIN=https://github.com/owner/repo.git"));
        assert!(
            push.lines()
                .any(|line| line == expected_server_pid.as_str())
        );
        assert!(
            push.lines()
                .any(|line| line == expected_server_pid_version.as_str())
        );
        assert!(
            push.lines()
                .any(|line| line == expected_server_digest.as_str())
        );
        assert!(observed.contains("GIT_CONFIG_GLOBAL=/dev/null"));
        assert!(!observed.contains("credential.interactive=never"));
        assert!(!observed.contains("PATH="));
        assert!(!observed.contains("HTTP_PROXY="));
        assert!(!observed.contains("HTTPS_PROXY="));
        assert!(!observed.contains(TOKEN));
        assert!(!tree_contains(&fixture.store_root, TOKEN.as_bytes()));
        assert!(!tree_contains(&fixture.workspace, TOKEN.as_bytes()));
        assert_ne!(result.process.stdout_digest.as_deref(), Some(TOKEN));
        assert_ne!(result.process.stderr_digest.as_deref(), Some(TOKEN));
        assert_eq!(result.credential_peer_served_count, 0);
        assert_eq!(result.credential_peer_rejected_count, 0);
    }

    #[test]
    fn credential_server_delivers_token_only_to_the_reviewed_process() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let uid = fs::symlink_metadata(&socket).unwrap().uid();
        let expected_digest = ExecutableDigest::from_sha256(
            identity::reviewed_executable_fingerprint(&std::env::current_exe().unwrap()).unwrap(),
        );
        let stop = AtomicBool::new(false);

        thread::scope(|scope| {
            let server = scope.spawn(|| {
                serve_credentials(
                    listener,
                    TOKEN,
                    std::process::id(),
                    uid,
                    expected_digest,
                    &stop,
                )
            });
            let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).unwrap();
            stop.store(true, Ordering::Release);
            let evidence = server.join().unwrap().unwrap();
            assert_eq!(received, TOKEN.as_bytes());
            assert_eq!(
                evidence,
                CredentialChannelEvidence {
                    served: 1,
                    rejected: 0,
                }
            );
        });
    }

    #[test]
    fn credential_server_refuses_an_unreviewed_descendant() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let uid = fs::symlink_metadata(&socket).unwrap().uid();
        let expected_digest = ExecutableDigest::from_sha256([0_u8; 32]);
        let stop = AtomicBool::new(false);

        thread::scope(|scope| {
            let server = scope.spawn(|| {
                serve_credentials(
                    listener,
                    TOKEN,
                    std::process::id(),
                    uid,
                    expected_digest,
                    &stop,
                )
            });
            let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).unwrap();
            stop.store(true, Ordering::Release);
            let evidence = server.join().unwrap().unwrap();
            assert!(received.is_empty());
            assert_eq!(
                evidence,
                CredentialChannelEvidence {
                    served: 0,
                    rejected: 1,
                }
            );
        });
    }

    #[test]
    fn credential_server_bounds_and_surfaces_rejected_attempts() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("credential.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let uid = fs::symlink_metadata(&socket).unwrap().uid();
        let stop = AtomicBool::new(false);

        thread::scope(|scope| {
            let server = scope.spawn(|| {
                serve_credentials(
                    listener,
                    TOKEN,
                    std::process::id(),
                    uid,
                    ExecutableDigest::from_sha256([0_u8; 32]),
                    &stop,
                )
            });
            for _ in 0..MAX_REJECTED_CREDENTIAL_ATTEMPTS {
                let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
                let mut received = Vec::new();
                client.read_to_end(&mut received).unwrap();
                assert!(received.is_empty());
            }
            let error = server.join().unwrap().unwrap_err();
            assert!(matches!(
                error,
                GitRunnerError::CredentialPeerRejectionLimit {
                    rejected: MAX_REJECTED_CREDENTIAL_ATTEMPTS
                }
            ));
        });
    }

    #[test]
    fn output_over_capture_limit_is_truncated_and_drained() {
        let output = vec![b'x'; OUTPUT_LIMIT as usize + 17];
        let expected = hex::encode(Sha256::digest(&output[..OUTPUT_LIMIT as usize]));

        assert_eq!(digest_bounded(Cursor::new(output)).unwrap(), expected);
    }

    #[test]
    fn oversized_subprocess_output_is_truncated_without_failing_the_run() {
        let fixture = Fixture::with_git_source(LARGE_OUTPUT_FAKE_GIT);
        let (artifact_ref, artifact) = fixture.verified_artifact();

        let result = fixture
            .runner
            .publish_with_token(
                &input(artifact_ref, "2222222222222222222222222222222222222222"),
                artifact,
                TOKEN,
            )
            .unwrap();
        let expected = hex::encode(Sha256::digest(vec![b' '; OUTPUT_LIMIT as usize]));

        assert_eq!(result.process.exit_code, Some(0));
        assert_eq!(
            result.process.stdout_digest.as_deref(),
            Some(expected.as_str())
        );
    }

    fn tree_contains(root: &Path, needle: &[u8]) -> bool {
        fs::read_dir(root).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                tree_contains(&path, needle)
            } else {
                fs::read(path)
                    .map(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
                    .unwrap_or(false)
            }
        })
    }

    #[test]
    fn reviewed_paths_must_be_absolute() {
        let error = ReviewedExecutable::new(PathBuf::from(OsStr::new("git")), [0; 32]).unwrap_err();
        assert!(matches!(
            error,
            GitRunnerError::ExecutablePathNotAbsolute(_)
        ));
    }
}
