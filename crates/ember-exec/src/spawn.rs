//! CLASSIFICATION: PUBLIC
//!
//! Privilege-boundary mechanisms for `ember-exec` (SCION-EMBER-EXEC-B-HASH-SETUID).
//!
//! Two responsibilities, deliberately kept side-effect-free at this layer:
//!
//! 1. [`verify_content_hash`] — blake3-hash the on-disk binary the daemon
//!    asked us to spawn and compare to the expected hex digest from the
//!    `SpawnDirective`. The hash gate is the CRIT-B mitigation: emberd
//!    pins ember-exec's blake3 before each container spawn, so a swap
//!    that puts a malicious binary in place must be detected before any
//!    `execve`. Returns a typed [`HashMismatchError`] on diff that the
//!    caller can turn into an `ExecFrame::HashMismatch` wire reply.
//!
//! 2. [`drop_privileges`] — wraps `nix::unistd::setresgid` +
//!    `nix::unistd::setresuid`, locking the real / effective / saved IDs
//!    to the target uid/gid in one syscall pair. After this returns
//!    `Ok(())`, the caller's process can no longer regain its original
//!    privileges, so the call MUST happen AFTER the hash check (so a
//!    failed verify can still log + close the connection from the
//!    pre-drop identity) and BEFORE any `execve` (so the child inherits
//!    the dropped credentials).
//!
//! Subtask C ([`SCION-EMBER-EXEC-C-SPAWN-INTEGRATION`]) wires both
//! mechanisms into the `SpawnDirective` handler. This module owns the
//! mechanisms; the orchestration lives in `main.rs` after C lands.

use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::pty::{encode_data_frame, encode_winsize_frame, pump_connection};
use crate::uds::{ExecFrame, FrameError, SpawnDirective, read_frame, write_frame};

/// `verify_content_hash` fails with this when the on-disk binary doesn't
/// match the expected hex. The actual hash is included so the daemon can
/// log a precise mismatch event and (in tests) compare against the known
/// good value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("content_hash mismatch for {path}: expected {expected}, actual {actual}")]
pub struct HashMismatchError {
    pub path: String,
    pub expected: String,
    pub actual: String,
}

/// Errors that can surface from [`verify_content_hash`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Mismatch(#[from] HashMismatchError),
}

/// Compute the blake3 hash of `binary_path` and compare to `expected_hex`
/// (lowercase hex, 64 chars). Returns `Ok(())` on match, a typed error
/// otherwise. Reads the file once with a streaming hasher; no full slurp.
pub fn verify_content_hash(binary_path: &Path, expected_hex: &str) -> Result<(), VerifyError> {
    let mut file = std::fs::File::open(binary_path).map_err(|e| VerifyError::Io {
        path: binary_path.display().to_string(),
        source: e,
    })?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| VerifyError::Io {
        path: binary_path.display().to_string(),
        source: e,
    })?;
    let actual = hasher.finalize().to_hex().to_string();
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(VerifyError::Mismatch(HashMismatchError {
            path: binary_path.display().to_string(),
            expected: expected_hex.to_string(),
            actual,
        }))
    }
}

/// Drop privileges to `target_uid` / `target_gid`. Calls `setresgid` first
/// (group identity has to drop before user identity, otherwise we lose
/// the ability to change groups), then `setresuid`. Each syscall locks
/// the real, effective, and saved IDs together — after a successful
/// return, the calling process cannot regain its original privileges.
///
/// Returns [`nix::Error`] verbatim so the caller can branch on
/// `EPERM` (not running as root, common in test) vs other failures.
///
/// On non-Linux targets (macOS, etc.) this returns `Err(nix::Error::ENOSYS)`.
/// The SCION ember-exec runtime only runs as root on Linux — macOS builds
/// compile clean but the privilege-drop path is unsupported at runtime.
// META-EMBER-EXEC-MACOS-BUILD-BREAK-SHIPPED-CHECKPOINT
#[cfg(target_os = "linux")]
pub fn drop_privileges(target_uid: u32, target_gid: u32) -> nix::Result<()> {
    use nix::unistd::{Gid, Uid, setresgid, setresuid};
    let gid = Gid::from_raw(target_gid);
    setresgid(gid, gid, gid)?;
    let uid = Uid::from_raw(target_uid);
    setresuid(uid, uid, uid)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn drop_privileges(_target_uid: u32, _target_gid: u32) -> nix::Result<()> {
    Err(nix::Error::ENOSYS)
}

/// Errors surfaced by [`handle_spawn_directive`]. The wire-level errors
/// (frame write failures) are surfaced separately from the spawn-side
/// errors so the caller can decide whether to drop the connection
/// (frame error) vs reply with a typed frame and continue.
#[derive(Debug, thiserror::Error)]
pub enum HandleSpawnError {
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),
    #[error("io error during spawn: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
}

/// SCION-EMBER-EXEC-C-SPAWN-INTEGRATION + SCION-EMBER-EXEC-D-PTY-WIRE: glue
/// handler that runs the full gated-spawn flow for a single `SpawnDirective`.
///
/// 1. Verify `binary_path` against `content_hash_expected`. On mismatch,
///    write `ExecFrame::HashMismatch { expected, actual }` and return —
///    no privilege change, no process spawn.
/// 2. (Production:) Drop privileges to the directive's `target_uid` /
///    `target_gid`. This slice intentionally SKIPS the drop in non-root
///    runs (geteuid != 0) so the same code path works in tests and on
///    a dev box; production deployments under SCION run ember-exec as
///    root and the drop fires for real.
/// 3. Spawn the binary inside a controlling pty via [`pump_connection`]
///    (the pty bridge from `pty.rs`). The peer's `ExecFrame::StdinBytes`
///    / `Resize` / `Signal` frames are translated into the pty's inner
///    TAG_DATA / TAG_WINSIZE wire shape and dispatched to the child via
///    the pty master; raw pty output is wrapped back into
///    `ExecFrame::OutputBytes` frames toward the peer.
/// 4. On child exit, write `ExecFrame::Exit { code }` and return.
///
// PtyBridge wired into handle_spawn_directive per SCION-EMBER-EXEC-D-PTY-WIRE:
// `pump_connection` owns the fork+pty+pump body; this handler owns the
// outer ExecFrame ↔ inner TAG_DATA/TAG_WINSIZE translation.
pub async fn handle_spawn_directive<S>(
    directive: SpawnDirective,
    stream: &mut S,
) -> Result<(), HandleSpawnError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Hash gate. Mismatch closes the connection without any privileged
    //    work (CRIT-B mitigation, per ADR 140).
    if let Err(VerifyError::Mismatch(m)) = verify_content_hash(
        Path::new(&directive.binary_path),
        &directive.content_hash_expected,
    ) {
        write_frame(
            stream,
            &ExecFrame::HashMismatch {
                expected: m.expected,
                actual: m.actual,
            },
        )
        .await?;
        return Ok(());
    }
    // IO errors on verify (missing file, etc.) propagate up — the caller
    // closes the connection.

    // 2. Privilege drop. Test runs as the current uid; production runs
    //    as root and drops to the directive's target_uid/target_gid.
    if nix::unistd::geteuid().is_root() {
        drop_privileges(directive.target_uid, directive.target_gid)
            .map_err(|e| std::io::Error::other(format!("drop_privileges: {e}")))?;
    }

    // 3. Pty bridge. We open an in-process `duplex` so `pump_connection`
    //    sees a stream that speaks its inner TAG_DATA / TAG_WINSIZE wire
    //    shape, while this handler translates between that and the outer
    //    `ExecFrame` JSON protocol on the peer-facing stream.
    let binary_path = directive.binary_path.clone();
    let argv = directive.argv.clone();
    let (peer_side, pump_side) = tokio::io::duplex(64 * 1024);

    // Spawn the pty pump as a background task; the handler runs the
    // translation loop in parallel.
    let pump_task =
        tokio::spawn(
            async move { pump_connection(pump_side, Path::new(&binary_path), &argv).await },
        );

    // Split the local end of the duplex so we can read pty output and
    // write framed input concurrently.
    let (mut pty_reader, mut pty_writer) = tokio::io::split(peer_side);

    // Translation loop: shuttles bytes/frames in both directions until the
    // pump task completes (child exited) or the peer closes the stream.
    let mut output_buf = [0u8; 4096];
    let mut peer_closed = false;
    loop {
        tokio::select! {
            // pty master → peer: raw bytes from the pump become OutputBytes
            // frames toward the peer.
            read_res = pty_reader.read(&mut output_buf) => {
                match read_res {
                    Ok(0) => {
                        // Pump dropped its write half — child exited or pump
                        // task finished. Break to reap the pump task.
                        break;
                    }
                    Ok(n) => {
                        write_frame(
                            stream,
                            &ExecFrame::OutputBytes {
                                bytes: output_buf[..n].to_vec(),
                            },
                        )
                        .await?;
                    }
                    Err(_) => break,
                }
            }

            // peer → pty master: decode ExecFrames and translate.
            frame_res = read_frame(stream), if !peer_closed => {
                match frame_res {
                    Ok(Some(ExecFrame::StdinBytes { bytes })) => {
                        let frame = encode_data_frame(&bytes);
                        if pty_writer.write_all(&frame).await.is_err() {
                            // Pump closed — child is dying; wait for output
                            // drain.
                            peer_closed = true;
                        }
                    }
                    Ok(Some(ExecFrame::Resize { rows, cols })) => {
                        let frame = encode_winsize_frame(rows, cols, 0, 0);
                        if pty_writer.write_all(&frame).await.is_err() {
                            peer_closed = true;
                        }
                    }
                    Ok(Some(ExecFrame::Signal { .. })) => {
                        // Signal delivery requires the child pid which the
                        // pump owns; routing it cleanly is follow-up scope.
                        // For now ignore signals — the peer can close the
                        // stream to terminate the child via SIGHUP on slave
                        // close instead.
                    }
                    Ok(Some(_)) => {
                        // Unexpected mid-session frame (SpawnDirective, etc.)
                        // — ignore.
                    }
                    Ok(None) => {
                        // Peer closed. Stop reading; the pump will keep
                        // draining the child until the pty master closes.
                        peer_closed = true;
                    }
                    Err(_) => {
                        peer_closed = true;
                    }
                }
            }
        }
    }

    // Drop the duplex writer half so the pump sees EOF on its inbound side.
    drop(pty_writer);
    // Drain any remaining pty output before the pump task finishes.
    loop {
        match pty_reader.read(&mut output_buf).await {
            Ok(0) => break,
            Ok(n) => {
                write_frame(
                    stream,
                    &ExecFrame::OutputBytes {
                        bytes: output_buf[..n].to_vec(),
                    },
                )
                .await?;
            }
            Err(_) => break,
        }
    }

    // 4. Reap the pump and emit Exit.
    let status = match pump_task.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(std::io::Error::other(format!("pump_connection: {e}")).into()),
        Err(e) => return Err(std::io::Error::other(format!("pump task join: {e}")).into()),
    };
    let code = status.code().unwrap_or(-1);
    write_frame(stream, &ExecFrame::Exit { code }).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn known_blake3(content: &[u8]) -> String {
        blake3::hash(content).to_hex().to_string()
    }

    #[test]
    fn verify_content_hash_matches_real_blake3() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let content = b"hello, ember-exec";
        f.write_all(content).unwrap();
        f.flush().unwrap();
        let expected = known_blake3(content);
        assert!(verify_content_hash(f.path(), &expected).is_ok());
    }

    #[test]
    fn verify_content_hash_matches_case_insensitive() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let content = b"mixed-case test";
        f.write_all(content).unwrap();
        f.flush().unwrap();
        let expected_upper = known_blake3(content).to_uppercase();
        assert!(verify_content_hash(f.path(), &expected_upper).is_ok());
    }

    #[test]
    fn verify_content_hash_rejects_mismatch() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"real content").unwrap();
        f.flush().unwrap();
        let wrong = "0".repeat(64);
        let result = verify_content_hash(f.path(), &wrong);
        match result {
            Err(VerifyError::Mismatch(HashMismatchError {
                actual, expected, ..
            })) => {
                assert_eq!(expected, wrong);
                assert_ne!(actual, wrong);
                // The actual must be the real blake3 of the file.
                assert_eq!(actual, blake3::hash(b"real content").to_hex().to_string());
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_content_hash_io_error_on_missing_file() {
        let result = verify_content_hash(Path::new("/nonexistent-ember-exec-test"), "0");
        assert!(matches!(result, Err(VerifyError::Io { .. })));
    }

    /// Smoke test for `drop_privileges`: calling it with the current uid/gid
    /// must succeed (we're already running as that uid). This does NOT
    /// exercise the actual privilege loss — that requires root + a target
    /// non-root uid — but it does verify the syscall path is wired.
    #[test]
    #[cfg(target_os = "linux")]
    fn drop_privileges_same_uid_smoke() {
        let cur_uid = nix::unistd::getuid().as_raw();
        let cur_gid = nix::unistd::getgid().as_raw();
        let result = drop_privileges(cur_uid, cur_gid);
        // setresgid/setresuid to the current ids succeed for any process,
        // root or not. We're verifying the call path doesn't panic and
        // returns Ok.
        assert!(
            result.is_ok(),
            "drop_privileges(current) failed: {result:?}"
        );
    }

    /// SCION-EMBER-EXEC-C-SPAWN-INTEGRATION: `handle_spawn_directive`
    /// runs the verify → spawn → exit flow end-to-end. We use `/bin/sh`
    /// (universally present on Linux/macOS) and hash it for a real
    /// content_hash_expected to exercise the OK branch.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn handle_spawn_directive_runs_and_emits_exit() {
        use crate::uds::ExecFrame;
        use tokio::io::duplex;

        let sh_path = "/bin/sh";
        if !std::path::Path::new(sh_path).exists() {
            // Skip on hosts without /bin/sh (e.g. some minimal containers).
            return;
        }
        let sh_hash = {
            let mut f = std::fs::File::open(sh_path).unwrap();
            let mut hasher = blake3::Hasher::new();
            std::io::copy(&mut f, &mut hasher).unwrap();
            hasher.finalize().to_hex().to_string()
        };
        let directive = SpawnDirective {
            binary_path: sh_path.to_string(),
            argv: vec!["sh".to_string(), "-c".to_string(), "exit 37".to_string()],
            env_allowlist: vec![],
            credential_env: vec![],
            target_uid: nix::unistd::getuid().as_raw(),
            target_gid: nix::unistd::getgid().as_raw(),
            content_hash_expected: sh_hash,
        };
        let (mut writer, mut reader) = duplex(64 * 1024);
        let handle =
            tokio::spawn(async move { handle_spawn_directive(directive, &mut writer).await });

        // Drain frames until we hit Exit; assert the exit code.
        let mut saw_exit = None;
        while let Ok(Some(frame)) = crate::uds::read_frame(&mut reader).await {
            if let ExecFrame::Exit { code } = frame {
                saw_exit = Some(code);
                break;
            }
        }
        handle.await.unwrap().unwrap();
        assert_eq!(saw_exit, Some(37), "expected Exit(37), got {saw_exit:?}");
    }

    /// Hash mismatch surfaces as `HashMismatch` frame — no spawn happens.
    #[tokio::test]
    #[cfg(unix)]
    async fn handle_spawn_directive_replies_hash_mismatch() {
        use crate::uds::ExecFrame;
        use tokio::io::duplex;

        let sh_path = "/bin/sh";
        if !std::path::Path::new(sh_path).exists() {
            return;
        }
        let directive = SpawnDirective {
            binary_path: sh_path.to_string(),
            argv: vec!["sh".to_string()],
            env_allowlist: vec![],
            credential_env: vec![],
            target_uid: nix::unistd::getuid().as_raw(),
            target_gid: nix::unistd::getgid().as_raw(),
            content_hash_expected: "0".repeat(64),
        };
        let (mut writer, mut reader) = duplex(64 * 1024);
        handle_spawn_directive(directive, &mut writer)
            .await
            .unwrap();
        let frame = crate::uds::read_frame(&mut reader).await.unwrap().unwrap();
        assert!(matches!(frame, ExecFrame::HashMismatch { .. }));
    }
}
