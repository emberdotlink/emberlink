//! CLASSIFICATION: PUBLIC
//!
//! Adversarially-safe env-derivation helpers for cohort-A trusted resolvers.
//!
//! These helpers turn cwd state (git remote, kubeconfig context,
//! `package.json`) into a target string the construct can synthesize into
//! the argv as an explicit flag. They are construct-internal: not
//! agent-supplied, not wrapped-binary-supplied. The wrapped binary's own
//! ergonomics (e.g. `gh`'s "infer repo from cwd") are deliberately bypassed
//! because the wrapped binary is the thing we are mediating — we cannot
//! delegate target derivation to it.
//!
//! The authority decision belongs to the daemon's `target ⊆ grant.resource`
//! clamp, NOT to these helpers. Their job ends at "produce a candidate
//! target string"; the daemon's gate decides whether the call may proceed.
//! Per operator 2026-06-11 lock (`feedback_grant_clamp_is_security_argv_is_ux`):
//! the grant clamp is security, argv ceremony is UX.
//!
//! ## Adversarial-cwd contract
//!
//! Every helper that runs a subprocess MUST:
//!
//! 1. **Path-pin the binary** — full absolute path (e.g. `/usr/bin/git`),
//!    NEVER PATH-resolved. The binary path is constant per process
//!    lifetime.
//! 2. **Content-hash-pin the binary** — blake3 the bytes on first
//!    successful access, cache the hash, refuse-with-loud-warning on
//!    subsequent mismatch (the binary changed under us; could be a
//!    legitimate OS update, but the operator should know).
//! 3. **Strip PATH** — subprocess inherits `PATH=""` so it cannot resolve
//!    other binaries (e.g. malicious `core.fsmonitor` helpers, credential
//!    helpers, askpass). Also strips HOME / XDG_CONFIG_HOME / config-env
//!    keys so global config does not perturb the answer.
//! 4. **No shell** — `Command::new(absolute)` with explicit args, never
//!    `sh -c`.
//! 5. **5-second wall-clock cap** — defends against `core.fsmonitor`
//!    daemons that never return and similar attacker-induced hangs.
//! 6. **4 KB stdout cap** — defends against output-fill DoS (a malicious
//!    `.git/config` could otherwise stuff arbitrary bytes into the pipe).
//! 7. **Treat the parsed output as a candidate string ONLY** — the
//!    daemon's `target ⊆ grant.resource` clamp is the authority gate.
//!
//! Anchor: `factory_resolver_framework_landed`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, Instant};

/// Canonical absolute path to the system `git` binary. The trusted
/// resolver never PATH-resolves; if `/usr/bin/git` is absent on a host
/// the helpers refuse and the existing `ResolverRequired` refusal stands.
pub const SYSTEM_GIT_BINARY: &str = "/usr/bin/git";

/// Maximum wall-clock time the helper allows a subprocess to run before
/// killing it. Defends against `core.fsmonitor` hangs and similar
/// attacker-induced waits.
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum stdout bytes the helper reads from a derivation subprocess.
/// A `.git/config` with a 100 KB origin URL would otherwise fill the
/// pipe.
const MAX_STDOUT_BYTES: usize = 4096;

/// One construct-internal git invoker bound to a single path-pinned
/// binary. The first successful invocation hashes the binary and caches
/// the fingerprint; later invocations refuse-and-warn on mismatch.
///
/// In production, callers use [`cwd_git_remote_origin_url`] which
/// dispatches against [`SYSTEM_GIT_RESOLVER`] (a process-wide
/// `LazyLock<GitRemoteResolver>` for `/usr/bin/git`). Tests build their
/// own [`GitRemoteResolver`] against a tempfile binary so the cached
/// hash does not leak between tests.
pub struct GitRemoteResolver {
    binary_path: PathBuf,
    pinned_hash: OnceLock<blake3::Hash>,
}

impl GitRemoteResolver {
    /// Build a resolver bound to the given binary path. The binary is
    /// not hashed until the first call so this is cheap.
    pub fn for_binary(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            pinned_hash: OnceLock::new(),
        }
    }

    /// Run `git -C <cwd> config --get remote.origin.url` and return the
    /// trimmed URL on success.
    ///
    /// Returns `None` when:
    /// - the pinned binary is missing or its content hash mismatches
    /// - the cwd is not a git repo, has no `origin` remote, or the
    ///   config is malformed
    /// - the subprocess takes longer than [`SUBPROCESS_TIMEOUT`]
    /// - the subprocess emits more than [`MAX_STDOUT_BYTES`]
    pub fn cwd_origin_url(&self, cwd: &Path) -> Option<String> {
        let binary = self.verified_binary()?;
        let cwd_arg = cwd.as_os_str().to_str()?;
        let stdout = spawn_with_timeout_and_bounded_stdout(
            binary,
            &["-C", cwd_arg, "config", "--get", "remote.origin.url"],
            SUBPROCESS_TIMEOUT,
            MAX_STDOUT_BYTES,
        )?;
        let text = std::str::from_utf8(&stdout).ok()?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(trimmed.to_string())
    }

    /// Verify the binary exists and its content hash matches the cache
    /// (or seed the cache on the first successful read). Returns the
    /// binary path on success; `None` on read-failure or hash-mismatch.
    fn verified_binary(&self) -> Option<&Path> {
        let bytes = std::fs::read(&self.binary_path).ok()?;
        let actual = blake3::hash(&bytes);
        match self.pinned_hash.get() {
            Some(pinned) if pinned == &actual => Some(self.binary_path.as_path()),
            Some(_pinned) => {
                tracing::warn!(
                    binary = %self.binary_path.display(),
                    "ember-construct env-derive: pinned binary content hash mismatch; refusing this call (operator: investigate the binary; OS update is benign, replacement is not)"
                );
                None
            }
            None => {
                // First successful read — seed the cache.
                let _ = self.pinned_hash.set(actual);
                Some(self.binary_path.as_path())
            }
        }
    }
}

/// Process-wide system-git resolver pinned to [`SYSTEM_GIT_BINARY`]. The
/// hash cache is per-process and persists across all
/// [`cwd_git_remote_origin_url`] calls.
static SYSTEM_GIT_RESOLVER: LazyLock<GitRemoteResolver> =
    LazyLock::new(|| GitRemoteResolver::for_binary(PathBuf::from(SYSTEM_GIT_BINARY)));

/// Convenience: derive `remote.origin.url` against the system git
/// binary. Production trusted-resolvers call this.
pub fn cwd_git_remote_origin_url(cwd: &Path) -> Option<String> {
    SYSTEM_GIT_RESOLVER.cwd_origin_url(cwd)
}

/// Spawn `binary` with `args` and `cwd`, collect stdout into a bounded
/// buffer, kill on timeout. All caller-visible side effects are
/// contained: env is cleared, no shell, no PATH, no stdin, stderr
/// discarded.
fn spawn_with_timeout_and_bounded_stdout(
    binary: &Path,
    args: &[&str],
    timeout: Duration,
    max_stdout: usize,
) -> Option<Vec<u8>> {
    let mut child = Command::new(binary)
        .args(args)
        .env_clear()
        // Explicit empty PATH so the subprocess cannot resolve other
        // binaries (askpass, credential helpers, core.fsmonitor).
        .env("PATH", "")
        // Defense-in-depth against git pulling global / XDG config.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", "")
        .env("XDG_CONFIG_HOME", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let mut stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let max = max_stdout;
    std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(256);
        // Read up to max+1 bytes so the caller can detect "exceeded cap."
        let mut limited = stdout.by_ref().take((max as u64) + 1);
        let _ = limited.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    }?;

    if !status.success() {
        // Drain reader thread before returning so it doesn't leak.
        let _ = rx.recv_timeout(Duration::from_millis(100));
        return None;
    }

    let buf = rx.recv_timeout(Duration::from_millis(500)).ok()?;
    if buf.len() > max_stdout {
        tracing::warn!(
            binary = %binary.display(),
            bytes = buf.len(),
            cap = max_stdout,
            "ember-construct env-derive: subprocess stdout exceeded cap; refusing"
        );
        return None;
    }
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC-1 (helper side): real /usr/bin/git in a real git repo returns
    /// the origin URL. Skipped when /usr/bin/git is missing.
    #[test]
    fn system_git_resolver_returns_origin_url_from_real_repo() {
        if !Path::new(SYSTEM_GIT_BINARY).exists() {
            eprintln!("skipping: {SYSTEM_GIT_BINARY} not present on this host");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let cwd = tmp.path();
        // git init + remote add via Command (the helper uses the same
        // binary, but here we set up state, not query it).
        let init = Command::new(SYSTEM_GIT_BINARY)
            .args(["init", "--quiet"])
            .current_dir(cwd)
            .output()
            .expect("git init");
        assert!(init.status.success(), "git init failed: {init:?}");
        let remote = Command::new(SYSTEM_GIT_BINARY)
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/acme/widgets.git",
            ])
            .current_dir(cwd)
            .output()
            .expect("git remote add");
        assert!(remote.status.success(), "git remote add failed: {remote:?}");

        let resolver = GitRemoteResolver::for_binary(PathBuf::from(SYSTEM_GIT_BINARY));
        let url = resolver.cwd_origin_url(cwd);
        assert_eq!(url.as_deref(), Some("https://github.com/acme/widgets.git"));
    }

    /// AC-2 (helper side): outside any git repo returns None.
    #[test]
    fn system_git_resolver_returns_none_outside_git_repo() {
        if !Path::new(SYSTEM_GIT_BINARY).exists() {
            eprintln!("skipping: {SYSTEM_GIT_BINARY} not present on this host");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let resolver = GitRemoteResolver::for_binary(PathBuf::from(SYSTEM_GIT_BINARY));
        assert_eq!(resolver.cwd_origin_url(tmp.path()), None);
    }

    /// AC-5 (helper side): if the pinned binary's content changes
    /// between calls, the second call refuses (returns None) and emits
    /// a loud warning. Soft-refusal — the operator can investigate and
    /// re-launch.
    #[test]
    fn pinned_binary_content_mismatch_refuses_second_call() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fake_binary = tmp.path().join("fake-git");

        // Write a minimal shell script that emulates `git config --get
        // remote.origin.url` for any args. Skipped if we can't make it
        // executable.
        std::fs::write(
            &fake_binary,
            b"#!/bin/sh\necho https://github.com/acme/v1.git\n",
        )
        .expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_binary, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }

        let resolver = GitRemoteResolver::for_binary(fake_binary.clone());
        let first = resolver.cwd_origin_url(tmp.path());
        // The script emits the URL regardless of args, so first must succeed.
        assert_eq!(first.as_deref(), Some("https://github.com/acme/v1.git"));

        // Rewrite the binary with different bytes.
        std::fs::write(
            &fake_binary,
            b"#!/bin/sh\necho https://github.com/evil/swap.git\n",
        )
        .expect("rewrite");
        let second = resolver.cwd_origin_url(tmp.path());
        assert_eq!(
            second, None,
            "pinned-hash mismatch must refuse on the second call"
        );
    }

    /// AC-6 (helper side): a subprocess that hangs past
    /// SUBPROCESS_TIMEOUT is killed and the helper returns None.
    #[test]
    fn subprocess_timeout_kills_and_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Use `/bin/sleep 60` indirectly via a shim script so we
        // exercise the timeout path against a real (slow) process.
        let shim = tmp.path().join("hanging-git");
        std::fs::write(&shim, b"#!/bin/sh\nsleep 60\n").expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        // Short timeout so the test stays fast.
        let started = Instant::now();
        let result = spawn_with_timeout_and_bounded_stdout(
            &shim,
            &["arg"],
            Duration::from_millis(250),
            MAX_STDOUT_BYTES,
        );
        let elapsed = started.elapsed();
        assert_eq!(result, None, "hung subprocess must be killed and refused");
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout must fire within ~2x the configured deadline (elapsed: {elapsed:?})"
        );
    }
}
