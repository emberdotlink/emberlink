//! Separate-uid daemon install scaffolding (ADR 131).
//!
//! `emberd` runs under a dedicated `ember` system uid in production so a
//! process running as the operator's uid cannot bypass the broker by reading
//! the vault directly (same-uid `ptrace`, `/proc/<pid>/environ`, SQLite file
//! access, keychain unlock all collapse the supervisor claim under single-
//! uid). This module owns the platform-specific provisioning that the
//! installer drives:
//!
//! 1. [`provision_ember_user`] — create the `ember` system user + the
//!    `ember-clients` group, add the invoking operator to `ember-clients`.
//! 2. [`chown_ember_data_dirs`] — recursively chown the daemon's data
//!    directory tree to `ember:ember-clients` and tighten file modes.
//! 3. [`install_launchd_plist`] (macOS) / [`install_systemd_unit`] (Linux)
//!    — write the platform launcher unit and bootstrap/enable the service.
//!
//! Both functions are **idempotent** — re-running on an already-provisioned
//! machine returns `Ok(())` without altering state. They shell out via
//! `std::process::Command` (no `nix` crate dep — matches the project's
//! existing subprocess-shellout pattern in `sandbox.rs` / `notify.rs`) and
//! always capture stderr per the `feedback_subprocess_logging` rule
//! (no `let _ = ...output()`).

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, Debug)]
struct AtomicFileMetadata {
    mode: Option<u32>,
    owner: Option<(libc::uid_t, libc::gid_t)>,
}

/// Errors raised by [`provision_ember_user`] and [`chown_ember_data_dirs`].
///
/// `Subprocess` is the dominant variant — every shell-out captures stderr
/// and the failing exit code so the installer can surface a useful
/// diagnostic. `Io` wraps filesystem reads (e.g. directory walks for the
/// chown traversal).
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("subprocess failed: cmd={cmd}, exit={exit_code:?}, stderr={stderr}")]
    Subprocess {
        cmd: String,
        stderr: String,
        exit_code: Option<i32>,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Returns true if `stderr` looks like a "user/group already exists" message
/// from the underlying provisioning tool. The check is intentionally broad —
/// macOS (`dseditgroup`, `sysadminctl`) and Linux (`groupadd`, `useradd`)
/// each phrase the condition slightly differently, so we fold the common
/// substrings into one helper.
///
/// ## macOS-version-dependent stderr surfaces
///
/// Apple surfaces "this record already exists, refusing to clobber" with
/// different stderr text across `dseditgroup`/`sysadminctl` releases:
///
/// | macOS version | exit code | stderr fragment |
/// |---|---|---|
/// | pre-macOS 26 | 1–73 | `"already exists"` |
/// | macOS 26+ (26.4 confirmed)  | 73 | `"could not be replaced"` (full: `"Operation cancelled because record could not be replaced"`) |
///
/// Both shapes mean "the user/group is already there — your -o create is a
/// no-op." This helper tolerates both. **Future macOS releases may surface
/// yet another shape.** If you hit a new exit code/stderr pair here, add a
/// row to the table above, widen the substring set below, and extend the
/// unit tests.
///
fn already_exists(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("already exists")
        || s.contains("already a member")
        || s.contains("could not be replaced")
}

/// Run a subprocess, capture stderr+exit code, and return them on failure.
///
/// `tolerate_already_exists`: when true, a non-zero exit whose stderr
/// matches [`already_exists`] is treated as success (idempotency).
fn run(program: &str, args: &[&str], tolerate_already_exists: bool) -> Result<(), InstallError> {
    let cmd_string = format!("{} {}", program, args.join(" "));
    let output =
        Command::new(program)
            .args(args)
            .output()
            .map_err(|e| InstallError::Subprocess {
                cmd: cmd_string.clone(),
                stderr: format!("spawn failed: {e}"),
                exit_code: None,
            })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let exit_code = output.status.code();

    if tolerate_already_exists && already_exists(&stderr) {
        return Ok(());
    }

    tracing::warn!(
        cmd = %cmd_string,
        exit = exit_code.unwrap_or(-1),
        stderr = %stderr,
        "subprocess failed"
    );
    Err(InstallError::Subprocess {
        cmd: cmd_string,
        stderr,
        exit_code,
    })
}

/// Atomically replace root-managed install artifacts whose mode/owner is set
/// immediately after write. Do not use this for mutable operator/config files
/// unless the caller deliberately preserves existing ownership semantics.
fn write_root_install_file_atomic(path: &Path, contents: &[u8]) -> Result<(), InstallError> {
    write_install_file_atomic(
        path,
        contents,
        AtomicFileMetadata {
            mode: None,
            owner: None,
        },
    )
}

/// Atomically write a file by creating a same-directory temp file and renaming
/// it into place. When metadata is supplied, apply it deliberately instead of
/// inheriting from the installer process.
fn write_install_file_atomic(
    path: &Path,
    contents: &[u8],
    metadata: AtomicFileMetadata,
) -> Result<(), InstallError> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| InstallError::Subprocess {
            cmd: format!("write {}", path.display()),
            stderr: "destination has no parent directory".to_string(),
            exit_code: None,
        })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("install-file");

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(".{file_name}.tmp-{}-{nanos}", std::process::id()));

    let cleanup_tmp = |tmp_path: &Path| {
        let _ = std::fs::remove_file(tmp_path);
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| InstallError::Subprocess {
            cmd: format!("create temp {}", tmp_path.display()),
            stderr: format!("open failed: {e}"),
            exit_code: None,
        })?;
    if let Some(mode) = metadata.mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| {
                cleanup_tmp(&tmp_path);
                InstallError::Subprocess {
                    cmd: format!("chmod {:04o} {}", mode, tmp_path.display()),
                    stderr: format!("set_permissions failed: {e}"),
                    exit_code: None,
                }
            })?;
    }
    if let Err(e) = file.write_all(contents) {
        cleanup_tmp(&tmp_path);
        return Err(InstallError::Subprocess {
            cmd: format!("write {}", tmp_path.display()),
            stderr: format!("write failed: {e}"),
            exit_code: None,
        });
    }
    if let Err(e) = file.sync_all() {
        cleanup_tmp(&tmp_path);
        return Err(InstallError::Subprocess {
            cmd: format!("sync {}", tmp_path.display()),
            stderr: format!("sync failed: {e}"),
            exit_code: None,
        });
    }
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        cleanup_tmp(&tmp_path);
        InstallError::Subprocess {
            cmd: format!("rename {} {}", tmp_path.display(), path.display()),
            stderr: format!("rename failed: {e}"),
            exit_code: None,
        }
    })?;

    if let Some((uid, gid)) = metadata.owner {
        let current_uid = unsafe { libc::geteuid() };
        let current_gid = unsafe { libc::getegid() };
        if uid != current_uid || gid != current_gid {
            chown_path(path, uid, gid)?;
        }
    }

    Ok(())
}

fn chown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<(), InstallError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let path_c =
        CString::new(path.as_os_str().as_bytes()).map_err(|e| InstallError::Subprocess {
            cmd: format!("chown {}", path.display()),
            stderr: format!("path contains NUL: {e}"),
            exit_code: None,
        })?;
    let rc = unsafe { libc::chown(path_c.as_ptr(), uid, gid) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(InstallError::Subprocess {
            cmd: format!("chown {}:{} {}", uid, gid, path.display()),
            stderr: format!("chown failed: {err}"),
            exit_code: Some(rc),
        });
    }
    Ok(())
}

fn copy_root_credential_file_atomic(src: &Path, dst: &Path) -> Result<(), InstallError> {
    let contents = std::fs::read(src).map_err(|e| InstallError::Subprocess {
        cmd: format!("read {}", src.display()),
        stderr: format!("read failed: {e}"),
        exit_code: None,
    })?;
    write_install_file_atomic(
        dst,
        &contents,
        AtomicFileMetadata {
            mode: Some(0o440),
            owner: None,
        },
    )
}

fn existing_regular_config_metadata(
    path: &Path,
) -> Result<Option<AtomicFileMetadata>, InstallError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(InstallError::Subprocess {
                cmd: format!("stat {}", path.display()),
                stderr: format!("symlink_metadata failed: {e}"),
                exit_code: None,
            });
        }
    };

    if meta.file_type().is_symlink() {
        return Err(InstallError::Subprocess {
            cmd: format!("stat {}", path.display()),
            stderr: "refusing to use symlinked daemon config path".to_string(),
            exit_code: None,
        });
    }
    if !meta.is_file() {
        return Err(InstallError::Subprocess {
            cmd: format!("stat {}", path.display()),
            stderr: "refusing to use non-file daemon config path".to_string(),
            exit_code: None,
        });
    }

    Ok(Some(AtomicFileMetadata {
        mode: Some(meta.permissions().mode() & 0o777),
        owner: Some((meta.uid(), meta.gid())),
    }))
}

/// Returns true if `id <user>` exits 0 (user exists). On spawn failure
/// (e.g. `id` missing) returns false — the subsequent provisioning command
/// will surface the real error.
fn user_exists(user: &str) -> bool {
    Command::new("id")
        .arg(user)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns `true` when the host is already on the **separate-uid posture**
/// (ADR 131): the dedicated `ember` system user exists.
///
/// Used by `ember daemon migrate` to short-circuit if the system is already
/// migrated so re-running is a documented no-op rather than partial mutation.
///
/// The check is intentionally lightweight — `id ember` is the canonical
/// probe for whether `provision_ember_user` was ever run successfully.
/// Callers that need finer-grained assertions (e.g. plist presence, data-dir
/// ownership) can combine this with platform-specific stat checks.
pub fn is_separate_uid_posture() -> bool {
    user_exists("ember")
}

/// Add `user` to the `group` via `dseditgroup -o edit`, then verify membership.
///
/// ## Why a dedicated wrapper (not `run(..., tolerate_already_exists: true)`)
///
/// On macOS 26 (26.4 confirmed), `dseditgroup -o edit -a <user> -t user <group>`
/// can exit non-zero with stderr `"Operation cancelled because record could not be
/// replaced"` on a path where the user was **not** actually added to the group.
/// PR #3061 widened [`already_exists`] to match `"could not be replaced"` — which
/// correctly handles `-o create` idempotency — but that same tolerance was
/// inherited by the `-o edit` (add-member) call inside [`provision_ember_user`].
/// The result: the installer returned `Ok(())` even though the operator was never
/// added, then `ember vault list` failed with `Permission denied` because the
/// socket is `0660 root:ember-clients`.
///
/// This function mirrors the [`bootout_tolerant_inner`] discipline:
/// 1. Accept the dseditgroup runner and a checkmember runner as injected closures
///    (testability — no real subprocess required in unit tests).
/// 2. Tolerate a non-zero exit ONLY when exit_code == 73 AND stderr contains
///    `"could not be replaced"` (macOS 26 shape). Any other failure propagates.
/// 3. After ANY tolerance (or on success), run the post-condition check:
///    `dseditgroup -o checkmember -m <user> <group>`. If membership is NOT
///    confirmed, surface a clear `InstallError::Subprocess` rather than
///    returning `Ok(())` silently.
///
#[cfg(target_os = "macos")]
fn dseditgroup_tolerant_inner<R, C>(
    cmd_string: &str,
    runner: R,
    checkmember: C,
) -> Result<(), InstallError>
where
    R: FnOnce() -> Result<(Option<i32>, String, bool), InstallError>,
    C: FnOnce() -> bool,
{
    let (exit_code, stderr, success) = runner()?;

    if !success {
        // Tolerate macOS 26+ "could not be replaced" ONLY when exit code is 73.
        // exit 73 is dseditgroup's "record manipulation failed" surface; any
        // other exit code is an unrelated failure we must not swallow.
        let is_macos26_already_member =
            exit_code == Some(73) && stderr.to_lowercase().contains("could not be replaced");

        if !is_macos26_already_member {
            tracing::warn!(
                cmd = %cmd_string,
                exit = exit_code.unwrap_or(-1),
                stderr = %stderr,
                "dseditgroup add-member failed"
            );
            return Err(InstallError::Subprocess {
                cmd: cmd_string.to_string(),
                stderr,
                exit_code,
            });
        }

        tracing::debug!(
            cmd = %cmd_string,
            "dseditgroup returned 'could not be replaced' (exit 73, macOS 26+ already-member shape); \
             verifying post-condition"
        );
    }

    // Post-condition: confirm the user is actually a member regardless of
    // which path we took (success OR tolerated). On macOS 26 the tolerated
    // path is the dangerous one — the user may not have been added.
    if !checkmember() {
        return Err(InstallError::Subprocess {
            cmd: cmd_string.to_string(),
            stderr: "dseditgroup reported success (or tolerated macOS 26 'could not be replaced') \
                 but post-condition check failed: user is NOT a member of the group. \
                 Run `sudo dseditgroup -o edit -a \"$USER\" -t user ember-clients` manually."
                .to_string(),
            exit_code,
        });
    }

    Ok(())
}

/// Canonical macOS `ember` user shape constants. See
/// `inspect_and_heal_ember_user_inner` for the policy that consumes these.
///
/// `EMBER_USER_HOME` and `EMBER_USER_SHELL` mirror the literals fed to
/// the explicit `dscl` create path in [`provision_ember_user`]; they are
/// the post-condition the installer asserts when an `ember` user already
/// exists from an earlier (possibly partial) install run.
#[cfg(target_os = "macos")]
const EMBER_USER_HOME: &str = "/var/empty";
#[cfg(target_os = "macos")]
const EMBER_USER_SHELL: &str = "/usr/bin/false";
#[cfg(target_os = "macos")]
const EMBER_USER_REALNAME: &str = "Emberlink Daemon";
#[cfg(target_os = "macos")]
const EMBER_USER_MIN_DYNAMIC_UID: u32 = 450;

/// macOS uses uids `< 500` for system users (Apple convention; the
/// Login window in `/System/Library/.../loginwindow.plist` hides
/// `Hide500Users=YES` by default). A uid `>= 500` means the existing
/// `ember` record came from a different package or a prior install that
/// allocated from the human-login range — renumbering it would orphan every
/// file the existing daemon already owns, so we refuse to heal it and
/// surface a remediation command instead.
#[cfg(target_os = "macos")]
const EMBER_USER_MAX_SYSTEM_UID: u32 = 500;

/// Snapshot of the `ember` user's directory-services record.
///
/// Returned by [`read_ember_user_shape_inner`]. `None` from the reader
/// distinguishes "property is unset" from "property is wrong" — the
/// inspector treats unset shell/home as a fixable divergence (run
/// `dscl . -change` to set it), while it treats a present-but-wrong uid
/// as a hard error (the "too wide" branch).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct EmberUserShape {
    uid: u32,
    home: Option<String>,
    shell: Option<String>,
}

/// Outcome of the pre-create inspect step that
/// [`inspect_and_heal_ember_user_inner`] returns.
///
/// Drives the macOS `provision_ember_user` flow:
/// - `Create` — the inspector confirmed the user is absent; run the
///   explicit `dscl` create path with a free daemon uid from the
///   reserved system-user range.
/// - `SkipHealthy` — the user is already present and matches the
///   canonical shape exactly; skip the create step.
/// - `HealedThenSkip` — the user is present but had narrow,
///   healable divergence (wrong shell, wrong home); the inspector
///   applied `dscl . -change` corrective ops listed in `changes` and
///   skipped the create step.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum EmberUserInspectAction {
    Create,
    SkipHealthy,
    HealedThenSkip { changes: Vec<String> },
}

/// Read the `ember` user's shape via an injected dscl property reader.
///
/// The reader closure receives the property name (e.g. `"UniqueID"`,
/// `"NFSHomeDirectory"`, `"UserShell"`) and returns:
/// - `Ok(Some(value))` — property is set; `value` is the trimmed
///   single-line value (stripped of the `<prop>: ` prefix dscl emits).
/// - `Ok(None)` — the property is unset OR the **user does not exist**.
///   The caller distinguishes these two cases by probing `UniqueID`
///   first: if `UniqueID` is `None`, the user is absent and the helper
///   returns `Ok(None)`.
/// - `Err(InstallError)` — the dscl invocation itself failed for an
///   unrelated reason (e.g. permission denied, command not found).
///
/// Real-subprocess wrapper: `dscl . -read /Users/ember <prop>` exits 0
/// when the user exists and emits `<prop>: <value>` on stdout; exits
/// non-zero with `eDSRecordNotFound` (`-14136`) when the user does not
/// exist.
///
/// Closure injection means unit tests can simulate any shape (canonical,
/// missing-shell, wrong-uid, absent) without touching real Open Directory.
///
#[cfg(target_os = "macos")]
fn read_ember_user_shape_inner<R>(mut reader: R) -> Result<Option<EmberUserShape>, InstallError>
where
    R: FnMut(&str) -> Result<Option<String>, InstallError>,
{
    let Some(uid_raw) = reader("UniqueID")? else {
        // UniqueID absent → user does not exist. (A user record without
        // a UniqueID is not a valid macOS user record; treat the same as
        // absent and let `provision_ember_user` run the create path.)
        return Ok(None);
    };
    let uid: u32 = uid_raw
        .trim()
        .parse::<u32>()
        .map_err(|e| InstallError::Subprocess {
            cmd: "dscl . -read /Users/ember UniqueID".to_string(),
            stderr: format!("UniqueID is not a valid u32 ({uid_raw:?}): {e}"),
            exit_code: None,
        })?;
    let home = reader("NFSHomeDirectory")?;
    let shell = reader("UserShell")?;
    Ok(Some(EmberUserShape { uid, home, shell }))
}

/// Inspect the existing `ember` user record and either confirm it is
/// canonical, heal narrow divergence, or surface a clear error.
///
/// Policy:
/// 1. **User absent** (`read_ember_user_shape_inner` returns `Ok(None)`):
///    return `EmberUserInspectAction::Create` so the caller runs the
///    normal create path.
/// 2. **User present + canonical** (uid in system range, home ==
///    `/var/empty`, shell == `/usr/bin/false`): return
///    `EmberUserInspectAction::SkipHealthy`.
/// 3. **User present + wrong shell or home**: apply narrow
///    `dscl . -change /Users/ember <prop> <current> <canonical>` ops
///    via the injected `changer` closure. On success return
///    `EmberUserInspectAction::HealedThenSkip` with the list of changes
///    applied (for the operator's logs). If `changer` returns an error
///    for any one corrective op, propagate it.
/// 4. **User present + wrong UID** (uid >= [`EMBER_USER_MAX_SYSTEM_UID`]):
///    refuse to heal — re-numbering the uid would orphan every file the
///    existing daemon already owns. Surface a clear
///    `InstallError::Subprocess` with the exact remediation command
///    (`sudo dseditgroup -o delete -g ember && sudo dscl . -delete
///    /Users/ember`) in the stderr field.
///
/// Closure injection on `changer` keeps the function testable without
/// real dscl mutation. `changer(prop, current, desired)` is invoked
/// once per divergent property.
///
#[cfg(target_os = "macos")]
fn inspect_and_heal_ember_user_inner<R, C>(
    reader: R,
    mut changer: C,
) -> Result<EmberUserInspectAction, InstallError>
where
    R: FnMut(&str) -> Result<Option<String>, InstallError>,
    C: FnMut(&str, &str, &str) -> Result<(), InstallError>,
{
    let Some(shape) = read_ember_user_shape_inner(reader)? else {
        return Ok(EmberUserInspectAction::Create);
    };

    // Hard error: uid is outside the system range. Renumbering would
    // orphan any file the existing daemon owns, so we refuse and surface
    // the manual remediation.
    if shape.uid >= EMBER_USER_MAX_SYSTEM_UID {
        return Err(InstallError::Subprocess {
            cmd: "inspect_and_heal_ember_user (uid out of system range)".to_string(),
            stderr: format!(
                "existing `ember` user has uid {} (>= {}), which is outside the macOS \
                 system-user range. This record came from a different package or a manual \
                 `dscl` install — renumbering it would orphan files the existing daemon \
                 already owns. Remediation: \
                 `sudo dseditgroup -o delete -g ember && sudo dscl . -delete /Users/ember`, \
                 then re-run `sudo ember daemon install`.",
                shape.uid, EMBER_USER_MAX_SYSTEM_UID
            ),
            exit_code: None,
        });
    }

    let mut changes = Vec::new();

    // Narrow corrective op: UserShell.
    let shell_current = shape.shell.as_deref().unwrap_or("");
    if shell_current != EMBER_USER_SHELL {
        changer("UserShell", shell_current, EMBER_USER_SHELL)?;
        changes.push(format!(
            "dscl . -change /Users/ember UserShell {shell_current:?} {EMBER_USER_SHELL:?}"
        ));
    }

    // Narrow corrective op: NFSHomeDirectory.
    let home_current = shape.home.as_deref().unwrap_or("");
    if home_current != EMBER_USER_HOME {
        changer("NFSHomeDirectory", home_current, EMBER_USER_HOME)?;
        changes.push(format!(
            "dscl . -change /Users/ember NFSHomeDirectory {home_current:?} {EMBER_USER_HOME:?}"
        ));
    }

    if changes.is_empty() {
        tracing::info!(
            uid = shape.uid,
            "ember user already present + canonical; skipping create"
        );
        Ok(EmberUserInspectAction::SkipHealthy)
    } else {
        tracing::info!(
            uid = shape.uid,
            changes = ?changes,
            "ember user present with narrow divergence; healed via dscl -change and skipping create"
        );
        Ok(EmberUserInspectAction::HealedThenSkip { changes })
    }
}

/// Real-subprocess wrapper: probe `ember` user shape via `dscl . -read`
/// then heal-or-surface via [`inspect_and_heal_ember_user_inner`].
///
/// Used by [`provision_ember_user`] to decide whether to run
/// the explicit `dscl` create path (user absent) or skip the create step
/// (user present + canonical, possibly after healing).
///
#[cfg(target_os = "macos")]
fn inspect_and_heal_ember_user() -> Result<EmberUserInspectAction, InstallError> {
    inspect_and_heal_ember_user_inner(
        |prop| {
            let output = Command::new("dscl")
                .args([".", "-read", "/Users/ember", prop])
                .output()
                .map_err(|e| InstallError::Subprocess {
                    cmd: format!("dscl . -read /Users/ember {prop}"),
                    stderr: format!("spawn failed: {e}"),
                    exit_code: None,
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                // eDSRecordNotFound / "DS Node not found" → user absent.
                // Treat as Ok(None) per the reader contract.
                if stderr.to_lowercase().contains("not found")
                    || stderr.contains("eDSRecordNotFound")
                {
                    return Ok(None);
                }
                return Err(InstallError::Subprocess {
                    cmd: format!("dscl . -read /Users/ember {prop}"),
                    stderr,
                    exit_code: output.status.code(),
                });
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            // dscl emits `<prop>: <value>` on a single line; multi-line
            // properties are emitted with `\n <value>` on subsequent lines.
            // For the three properties we read (UniqueID, NFSHomeDirectory,
            // UserShell), the value is always single-line.
            let value = stdout
                .lines()
                .next()
                .and_then(|first| first.strip_prefix(&format!("{prop}: ")))
                .map(|s| s.trim().to_string());
            Ok(value)
        },
        |prop, current, desired| {
            // `dscl . -change <path> <prop> <oldvalue> <newvalue>` — the
            // old-value argument is required even when we just want to
            // overwrite; passing the current value (possibly empty) is
            // the canonical pattern.
            run(
                "dscl",
                &[".", "-change", "/Users/ember", prop, current, desired],
                false,
            )
        },
    )
}

#[cfg(target_os = "macos")]
fn ember_group_gid() -> Option<libc::gid_t> {
    use std::ffi::CString;
    let cgroup = CString::new("ember").ok()?;
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            cgroup.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(grp.gr_gid)
}

#[cfg(target_os = "macos")]
fn system_uid_is_occupied(uid: u32) -> bool {
    // SAFETY: `getpwuid` is thread-safe for read-only probing on Darwin when
    // the returned pointer is inspected immediately and not retained.
    unsafe { !libc::getpwuid(uid as libc::uid_t).is_null() }
}

#[cfg(target_os = "macos")]
fn allocate_ember_system_uid_inner<F>(mut is_occupied: F) -> Result<u32, InstallError>
where
    F: FnMut(u32) -> bool,
{
    for uid in EMBER_USER_MIN_DYNAMIC_UID..EMBER_USER_MAX_SYSTEM_UID {
        if !is_occupied(uid) {
            return Ok(uid);
        }
    }
    Err(InstallError::Subprocess {
        cmd: "allocate_ember_system_uid".to_string(),
        stderr: format!(
            "no free macOS system uid available in reserved range {}..{}",
            EMBER_USER_MIN_DYNAMIC_UID,
            EMBER_USER_MAX_SYSTEM_UID - 1
        ),
        exit_code: None,
    })
}

#[cfg(target_os = "macos")]
fn allocate_ember_system_uid() -> Result<u32, InstallError> {
    allocate_ember_system_uid_inner(system_uid_is_occupied)
}

#[cfg(target_os = "macos")]
fn create_ember_user_dscl_args(uid: u32, primary_gid: libc::gid_t) -> Vec<Vec<String>> {
    let uid_str = uid.to_string();
    let gid_str = primary_gid.to_string();
    let user_path = "/Users/ember".to_string();
    vec![
        vec![".".to_string(), "-create".to_string(), user_path.clone()],
        vec![
            ".".to_string(),
            "-create".to_string(),
            user_path.clone(),
            "RealName".to_string(),
            EMBER_USER_REALNAME.to_string(),
        ],
        vec![
            ".".to_string(),
            "-create".to_string(),
            user_path.clone(),
            "UniqueID".to_string(),
            uid_str,
        ],
        vec![
            ".".to_string(),
            "-create".to_string(),
            user_path.clone(),
            "PrimaryGroupID".to_string(),
            gid_str,
        ],
        vec![
            ".".to_string(),
            "-create".to_string(),
            user_path.clone(),
            "UserShell".to_string(),
            EMBER_USER_SHELL.to_string(),
        ],
        vec![
            ".".to_string(),
            "-create".to_string(),
            user_path,
            "NFSHomeDirectory".to_string(),
            EMBER_USER_HOME.to_string(),
        ],
    ]
}

#[cfg(target_os = "macos")]
fn create_ember_user() -> Result<(), InstallError> {
    let ember_gid = ember_group_gid().ok_or_else(|| InstallError::Subprocess {
        cmd: "getgrnam_r ember".to_string(),
        stderr: "the `ember` group is not provisioned — group creation must succeed before user creation"
            .to_string(),
        exit_code: None,
    })?;
    let ember_uid = allocate_ember_system_uid()?;
    for argv in create_ember_user_dscl_args(ember_uid, ember_gid) {
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        run("dscl", &argv_refs, false)?;
    }
    Ok(())
}

/// Real-subprocess wrapper: add `user` to `group` via `dseditgroup -o edit`,
/// then verify with `dseditgroup -o checkmember -m <user> <group>`.
#[cfg(target_os = "macos")]
fn dseditgroup_add_operator_to_group(user: &str, group: &str) -> Result<(), InstallError> {
    let cmd_string = format!("dseditgroup -o edit -a {user} -t user {group}");
    let cmd_for_runner = cmd_string.clone();
    let user_owned = user.to_string();
    let group_owned = group.to_string();
    let group_for_checker = group.to_string();
    let user_for_checker = user.to_string();
    dseditgroup_tolerant_inner(
        &cmd_string,
        move || {
            let output = Command::new("dseditgroup")
                .args(["-o", "edit", "-a", &user_owned, "-t", "user", &group_owned])
                .output()
                .map_err(|e| InstallError::Subprocess {
                    cmd: cmd_for_runner.clone(),
                    stderr: format!("spawn failed: {e}"),
                    exit_code: None,
                })?;
            let exit_code = output.status.code();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Ok((exit_code, stderr, output.status.success()))
        },
        move || {
            // `dseditgroup -o checkmember -m <user> <group>` exits 0 when the
            // user is a member, non-zero otherwise.
            Command::new("dseditgroup")
                .args([
                    "-o",
                    "checkmember",
                    "-m",
                    &user_for_checker,
                    &group_for_checker,
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        },
    )
}

/// Provision the `ember` system user + the `ember-clients` connect group.
///
/// **Idempotent.** Re-running on an already-provisioned machine returns
/// `Ok(())` without altering state — every step tolerates the platform's
/// "already exists" stderr signature.
///
/// On macOS:
/// - `dseditgroup -o create ember` — group create (idempotent).
/// - **Inspect-and-heal step** (see [`inspect_and_heal_ember_user_inner`]):
///   probe the existing `ember` user via `dscl . -read /Users/ember`; if
///   absent run the explicit `dscl` create path with a free system uid in
///   the reserved range `{EMBER_USER_MIN_DYNAMIC_UID}..499`; if present + canonical skip the
///   create; if present with narrow divergence (wrong shell, wrong home)
///   heal via `dscl . -change`; if present with wide divergence (uid
///   outside the system range) surface a hard `InstallError` with the
///   manual remediation command. Replaces the naive `if !id ember` check
///   that silently kept divergent records around.
/// - `dseditgroup -o create ember-clients` — connect-group create.
/// - `dseditgroup -o edit -a "$USER" -t user ember-clients` — add the
///   invoking operator to the connect group.
///
/// On Linux:
/// - `groupadd --system --force ember` — system group create (idempotent
///   via `--force`).
/// - `useradd --system --shell /usr/sbin/nologin --gid ember ember` only
///   when `id ember` reports the user is missing.
/// - `groupadd --system --force ember-clients` — connect-group create.
/// - `usermod -aG ember-clients $USER` — add the invoking operator to
///   the connect group.
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point).
#[cfg(target_os = "macos")]
pub fn provision_ember_user() -> Result<(), InstallError> {
    // 1) ember group
    run("dseditgroup", &["-o", "create", "ember"], true)?;

    // 2) ember user — inspect-and-heal before any create.
    //
    // A previous
    // partial install (or a different package that also created an `ember`
    // record) can leave the user present with wrong shape (e.g. shell !=
    // /usr/bin/false). The naive `if !user_exists` check skipped user creation
    // but never normalized the divergent fields; downstream consumers
    // (launchd plist, vault sockets) then hit cryptic permission errors.
    //
    // `inspect_and_heal_ember_user` returns one of three actions:
    // - Create        → user absent, run the explicit dscl create path
    // - SkipHealthy   → user present + canonical shape, skip create
    // - HealedThenSkip → user present with narrow divergence; dscl . -change
    //                    ops applied; skip create
    //
    // Wide divergence (uid outside the system range) surfaces an
    // InstallError with the manual remediation command.
    let action = inspect_and_heal_ember_user()?;
    if matches!(action, EmberUserInspectAction::Create) {
        create_ember_user()?;
    }

    // 3) ember-clients connect group
    run("dseditgroup", &["-o", "create", "ember-clients"], true)?;

    // 4) add the ember user to ember-clients
    //
    // The
    // launchd plist's `GroupName=ember-clients` (formerly `ember` — a group
    // that was never created on macOS, falling back silently to `staff`)
    // requires the ember user to be a member of `ember-clients` so launchd's
    // primary-group lookup resolves to it. Without this membership, the
    // daemon ends up running with `staff` as its primary group (gid 20),
    // making every daemon-created file world-readable to any local user.
    run(
        "dseditgroup",
        &["-o", "edit", "-a", "ember", "-t", "user", "ember-clients"],
        true,
    )?;

    // 5) add invoking operator to ember-clients
    //
    // Use `dseditgroup_add_operator_to_group` instead of the generic `run`
    // helper: the generic helper's `tolerate_already_exists=true` flag matched
    // "could not be replaced" (macOS 26 surface) even when the user was NOT
    // actually added to the group. The dedicated wrapper tightens the tolerance
    // to exit_code==73 && stderr contains "could not be replaced" AND verifies
    // membership via a post-condition checkmember call before returning Ok.
    let invoking_user = std::env::var("USER").unwrap_or_default();
    if !invoking_user.is_empty() {
        dseditgroup_add_operator_to_group(&invoking_user, "ember-clients")?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn provision_ember_user() -> Result<(), InstallError> {
    // 1) ember system group (idempotent via --force)
    run("groupadd", &["--system", "--force", "ember"], true)?;

    // 2) ember user (only if missing)
    if !user_exists("ember") {
        run(
            "useradd",
            &[
                "--system",
                "--shell",
                "/usr/sbin/nologin",
                "--gid",
                "ember",
                "ember",
            ],
            true,
        )?;
    }

    // 3) ember-clients connect group
    run("groupadd", &["--system", "--force", "ember-clients"], true)?;

    // 4) add invoking operator to ember-clients
    let invoking_user = std::env::var("USER").unwrap_or_default();
    if !invoking_user.is_empty() {
        run("usermod", &["-aG", "ember-clients", &invoking_user], true)?;
    }

    Ok(())
}

/// Fallback for platforms other than macOS/Linux. The `emberd` install
/// flow is only supported on macOS + Linux (per ADR 131); other targets
/// surface a clear error rather than silently no-op.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn provision_ember_user() -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "provision_ember_user".to_string(),
        stderr:
            "unsupported platform: ember user provisioning is implemented only for macOS and Linux"
                .to_string(),
        exit_code: None,
    })
}

// Per-spawn uid pool provisioning.
// The installer creates N `ember-spawn-<i>` system users with
// pre-assigned uids in the 10010-10099 range. The daemon's
// `[spawn_pool]` config references this set. See ADR 167 (amendment
// to ADR 131) for rationale.

/// Default size of the per-spawn uid pool. Matches the autopilot
/// fanout cap (8 concurrent agents) — production deployments can
/// raise this via `--spawn-pool-size <N>` on `ember daemon install`.
pub const DEFAULT_SPAWN_POOL_SIZE: usize = 8;

/// First uid in the reserved per-spawn range. Chosen above the
/// typical Linux `useradd --system` default (100-999) and above
/// macOS's reserved-user range (501-999 for ordinary users) but
/// well below 60000 (the LDAP/AD threshold many sites use).
pub const SPAWN_POOL_UID_BASE: u32 = 10010;

/// Last allowed uid in the reserved per-spawn range (exclusive).
/// 10010..10100 gives 90 slots — far more than any realistic
/// fanout depth.
pub const SPAWN_POOL_UID_MAX: u32 = 10100;

/// ADR 155 Component 2 modern-Linux subuid range start. Chosen above
/// the typical Linux `useradd --system` default (100-999) and the
/// reserved-user range (1000-65535) most distros use, but below the
/// 60000 LDAP/AD threshold many sites enforce. 100000 is the
/// `newuidmap` / `shadow-utils` convention for unprivileged user
/// namespace base.
pub const SUBUID_RANGE_START: u32 = 100_000;

/// ADR 155 Component 2 modern-Linux subuid range size — 8192-slot
/// pool. Matches the autopilot fanout build target and the
/// `unprivileged_userns_clone` clone3-spawn module's pool size.
pub const SUBUID_RANGE_SLOTS: u32 = 8192;

/// Result of spawn-pool provisioning. Captures the three modes the
/// installer can land in:
///
/// 1. **`Subuid`** — ADR 155 Component 2 modern-Linux path. The
///    installer wrote a `/etc/subuid` + `/etc/subgid` entry granting
///    `ember` an unprivileged subuid range; the daemon uses
///    `clone3(CLONE_NEWUSER | ...)` at spawn time and maps the
///    subuid range into the new namespace. No system users to
///    create — the range is purely a kernel-side mapping.
///
/// 2. **`SystemUsers`** — ADR 131 separate-uid posture (the
///    pre-ADR-155 path) and ADR 155's hardened-Linux + macOS path.
///    The installer creates `ember-spawn-<N>` system users with
///    pre-assigned uids in [`SPAWN_POOL_UID_BASE`]..
///    [`SPAWN_POOL_UID_MAX`] and the daemon `setresuid`'s into one
///    of those uids before exec.
///
/// 3. **`ManualCommands`** — non-root install path (typically macOS
///    without admin). The installer could not provision the pool
///    itself; the operator must run the surfaced `sudo ...`
///    commands. The installer surfaces both the commands and the
///    uids the operator should end up with so the resulting
///    `config.toml` is correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnPoolProvisioning {
    /// Modern-Linux subuid range path (ADR 155 Component 2). The
    /// installer wrote `ember:{range_start}:{slot_count}` to
    /// `/etc/subuid` and `/etc/subgid`.
    Subuid {
        /// First uid in the granted subuid range (inclusive).
        range_start: u32,
        /// Number of consecutive uids granted in the range.
        slot_count: u32,
    },
    /// System-user pool (ADR 131 + ADR 155 hardened-Linux/macOS
    /// paths). The installer created `ember-spawn-<N>` system users.
    SystemUsers {
        /// Uids that were provisioned (or are already present + verified).
        uids: Vec<u32>,
        /// Shared gid for the pool. The installer ensures every
        /// `ember-spawn-<i>` user has this gid as their primary group.
        gid: u32,
    },
    /// Non-root install path: installer surfaces the `sudo ...`
    /// commands the operator must run manually, plus the expected
    /// pool layout the resulting config should reflect.
    ManualCommands {
        /// Expected uids once the operator runs the manual commands.
        uids: Vec<u32>,
        /// Expected gid once the operator runs the manual commands.
        gid: u32,
        /// Commands the operator should run with sudo.
        commands: Vec<String>,
    },
}

/// Provision a pool of `pool_size` ephemeral spawn users. Idempotent:
/// existing pool users with matching uids in the reserved range are
/// detected via `getpwnam` and skipped.
///
/// Linux path: creates `ember-spawn-<i>` system users via `useradd`,
/// each with the same `ember-spawn` primary group + `ember-clients`
/// supplementary group.
///
/// macOS path: uses `dscl . -create /Users/ember-spawn-<i>` with a
/// pre-assigned `UniqueID` (uid). Falls back to surfacing the
/// dscl commands as `manual_commands` when the installer is not
/// running as root.
pub fn provision_spawn_pool(pool_size: usize) -> Result<SpawnPoolProvisioning, InstallError> {
    if pool_size == 0 {
        return Err(InstallError::Subprocess {
            cmd: "provision_spawn_pool".to_string(),
            stderr: "pool_size must be > 0".to_string(),
            exit_code: None,
        });
    }
    let last_uid = SPAWN_POOL_UID_BASE + pool_size as u32;
    if last_uid > SPAWN_POOL_UID_MAX {
        return Err(InstallError::Subprocess {
            cmd: "provision_spawn_pool".to_string(),
            stderr: format!(
                "pool_size {pool_size} exceeds reserved uid range ({SPAWN_POOL_UID_BASE}..{SPAWN_POOL_UID_MAX})"
            ),
            exit_code: None,
        });
    }
    provision_spawn_pool_impl(pool_size)
}

#[cfg(target_os = "linux")]
fn provision_spawn_pool_impl(pool_size: usize) -> Result<SpawnPoolProvisioning, InstallError> {
    // 1) Create the shared `ember-spawn` primary group. We use a
    //    dedicated group (not `ember-clients`) so the pool users
    //    don't pick up ember-clients' connect-group authority.
    run("groupadd", &["--system", "--force", "ember-spawn"], true)?;

    let mut uids = Vec::with_capacity(pool_size);
    for i in 0..pool_size {
        let uid = SPAWN_POOL_UID_BASE + i as u32;
        let user = format!("ember-spawn-{i}");
        if user_exists(&user) {
            // Already provisioned. Trust the existing uid assignment;
            // the installer is idempotent.
            uids.push(uid);
            continue;
        }
        let uid_str = uid.to_string();
        run(
            "useradd",
            &[
                "--system",
                "--shell",
                "/usr/sbin/nologin",
                "--no-create-home",
                "--uid",
                &uid_str,
                "--gid",
                "ember-spawn",
                &user,
            ],
            true,
        )?;
        uids.push(uid);
    }

    // Resolve the gid for `ember-spawn` via getent group.
    let output = Command::new("getent")
        .args(["group", "ember-spawn"])
        .output()
        .map_err(|e| InstallError::Subprocess {
            cmd: "getent group ember-spawn".to_string(),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        })?;
    let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // Format: `ember-spawn:x:<gid>:`
    let gid = line
        .split(':')
        .nth(2)
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| InstallError::Subprocess {
            cmd: "getent group ember-spawn".to_string(),
            stderr: format!("unexpected getent output: {line:?}"),
            exit_code: None,
        })?;

    Ok(SpawnPoolProvisioning::SystemUsers { uids, gid })
}

#[cfg(target_os = "macos")]
fn provision_spawn_pool_impl(pool_size: usize) -> Result<SpawnPoolProvisioning, InstallError> {
    // macOS lacks `useradd` — we go through `dscl`. The pool's
    // shared group is `ember-spawn`, created idempotently via
    // `dseditgroup -o create`. dscl needs admin to mutate
    // `/Users` and `/Groups`; when not running as root we surface
    // the commands as `manual_commands` for the operator instead
    // of half-shipping a broken state.
    let running_as_root = unsafe { libc::geteuid() } == 0;
    let mut manual = Vec::new();

    if running_as_root {
        run("dseditgroup", &["-o", "create", "ember-spawn"], true)?;
    } else {
        manual.push("sudo dseditgroup -o create ember-spawn".to_string());
    }

    let mut uids = Vec::with_capacity(pool_size);
    for i in 0..pool_size {
        let uid = SPAWN_POOL_UID_BASE + i as u32;
        let user = format!("ember-spawn-{i}");
        uids.push(uid);

        if user_exists(&user) {
            continue;
        }

        let uid_str = uid.to_string();
        let user_path = format!("/Users/{user}");
        if running_as_root {
            run("dscl", &[".", "-create", &user_path], false)?;
            run(
                "dscl",
                &[".", "-create", &user_path, "UniqueID", &uid_str],
                false,
            )?;
            // PrimaryGroupID — gid 0 (wheel) is safe as long as the
            // user has no shell. Real production hosts should add a
            // matching numeric gid; we surface that as a follow-up.
            run(
                "dscl",
                &[".", "-create", &user_path, "PrimaryGroupID", "0"],
                false,
            )?;
            run(
                "dscl",
                &[".", "-create", &user_path, "UserShell", "/usr/bin/false"],
                false,
            )?;
            run(
                "dscl",
                &[".", "-create", &user_path, "NFSHomeDirectory", "/var/empty"],
                false,
            )?;
        } else {
            manual.push(format!("sudo dscl . -create {user_path}"));
            manual.push(format!(
                "sudo dscl . -create {user_path} UniqueID {uid_str}"
            ));
            manual.push(format!("sudo dscl . -create {user_path} PrimaryGroupID 0"));
            manual.push(format!(
                "sudo dscl . -create {user_path} UserShell /usr/bin/false"
            ));
            manual.push(format!(
                "sudo dscl . -create {user_path} NFSHomeDirectory /var/empty"
            ));
        }
    }

    // dscl exposes the gid via a follow-up read. We use the wheel gid
    // (0) here for simplicity — the production Linux path uses a
    // dedicated `ember-spawn` gid. macOS is a development surface for
    // this feature; ADR 131 limits the separate-uid posture to Linux
    // production hosts.
    let gid = 0;

    if manual.is_empty() {
        Ok(SpawnPoolProvisioning::SystemUsers { uids, gid })
    } else {
        Ok(SpawnPoolProvisioning::ManualCommands {
            uids,
            gid,
            commands: manual,
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn provision_spawn_pool_impl(_pool_size: usize) -> Result<SpawnPoolProvisioning, InstallError> {
    Err(InstallError::Subprocess {
        cmd: "provision_spawn_pool".to_string(),
        stderr:
            "unsupported platform: spawn pool provisioning is implemented only for macOS and Linux"
                .to_string(),
        exit_code: None,
    })
}

/// Render the `[spawn_pool]` TOML section for the daemon config.
/// Returns a string the installer can append to `~/.ember/config.toml`
/// (or write into a fresh config when the operator has none).
///
/// Three shapes depending on the provisioning variant:
///
/// - [`SpawnPoolProvisioning::Subuid`] — renders an
///   `subuid_range_start` + `subuid_range_slots` pair (ADR 155
///   Component 2). The daemon's clone3-spawn module reads these and
///   maps the range into the user namespace at spawn time.
/// - [`SpawnPoolProvisioning::SystemUsers`] — renders the
///   `uids = [...]` + `gid = N` shape (ADR 131 + ADR 155
///   hardened-Linux/macOS).
/// - [`SpawnPoolProvisioning::ManualCommands`] — renders the same
///   shape as `SystemUsers` (the expected end-state); the
///   installer surfaces the manual commands separately.
pub fn render_spawn_pool_toml(provisioning: &SpawnPoolProvisioning) -> String {
    match provisioning {
        SpawnPoolProvisioning::Subuid {
            range_start,
            slot_count,
        } => format!(
            "\n[spawn_pool]\n# META-EXEC-DOMAIN-SUBUID-INSTALL — ADR 155 Component 2\n# modern-Linux subuid range. The daemon calls `clone3(CLONE_NEWUSER \\\n# | ...)` at spawn time, becomes namespace-owner (kernel grants all\n# caps inside the new namespace), then setresuid's to a uid mapped\n# from this range. No system users to provision — the kernel-side\n# `/etc/subuid` entry IS the pool.\nsubuid_range_start = {range_start}\nsubuid_range_slots = {slot_count}\n"
        ),
        SpawnPoolProvisioning::SystemUsers { uids, gid }
        | SpawnPoolProvisioning::ManualCommands { uids, gid, .. } => {
            let uids_str = uids
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "\n[spawn_pool]\n# META-BROKER-EXEC-PER-SPAWN-UID — per-spawn uid pool. The daemon\n# leases a uid from this set before fork+execve in `broker_exec`.\nuids = [{uids_str}]\ngid = {gid}\n"
            )
        }
    }
}


/// Remove an existing top-level `[spawn_pool]` table (header + its body up to
/// the next top-level table header or EOF) from `config.toml` text, preserving
/// every other section verbatim. Returns the text without the section.
///
/// The only writer of `[spawn_pool]` is [`render_spawn_pool_toml`], which emits
/// the canonical `\n[spawn_pool]\n# ...\n<keys>` shape, so an exact-match on the
/// trimmed header line is sufficient and avoids a full TOML re-serialize (which
/// would strip the operator's comments elsewhere in the file).
fn strip_spawn_pool_section(text: &str) -> String {
    let mut out = String::new();
    let mut in_section = false;
    for line in text.lines() {
        if in_section {
            // Any new top-level table header ends the spawn_pool section.
            if line.trim_start().starts_with('[') {
                in_section = false;
            } else {
                continue; // still inside [spawn_pool] — drop the line
            }
        }
        if line.trim() == "[spawn_pool]" {
            in_section = true;
            continue; // drop the header; it will be re-rendered
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Idempotently upsert the provisioned `[spawn_pool]` section into the
/// daemon's system `config.toml` (per ADR 218 — `DaemonPaths::system().
/// config_file()`).
///
/// The daemon (`emberd`) reads `[spawn_pool]` from this file. Without this
/// section `broker_exec` has no uid pool to lease and refuses to dispatch
/// — so the spawn-helper plist alone is not enough; the daemon must also
/// learn the pool. Any pre-existing `[spawn_pool]` block is replaced;
/// all other sections are preserved verbatim.
///
/// `operator_home` is retained for call-site stability and is unused —
/// the file now lives at the system config path, not under `$HOME`.
pub fn write_spawn_pool_config(
    _operator_home: &Path,
    provisioning: &SpawnPoolProvisioning,
) -> Result<(), InstallError> {
    write_spawn_pool_config_inner(&crate::paths::DaemonPaths::system(), provisioning)
}

/// Inner helper: factored out so tests can pass `DaemonPaths::for_test(tmp)`
/// and exercise the upsert + section-preservation logic without writing to
/// real system paths.
fn write_spawn_pool_config_inner(
    paths: &crate::paths::DaemonPaths,
    provisioning: &SpawnPoolProvisioning,
) -> Result<(), InstallError> {
    let config_path = paths.config_file();
    let rewrite_metadata = existing_regular_config_metadata(&config_path)?;

    let existing = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(InstallError::Subprocess {
                cmd: format!("read {}", config_path.display()),
                stderr: format!("read failed: {e}"),
                exit_code: None,
            });
        }
    };

    let stripped = strip_spawn_pool_section(&existing);
    let section = render_spawn_pool_toml(provisioning);

    // `section` begins with a leading newline; normalize so there is exactly
    // one blank line between the preserved body and the section.
    let mut out = stripped.trim_end().to_string();
    out.push('\n');
    out.push_str(section.trim_start_matches('\n'));

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InstallError::Subprocess {
            cmd: format!("mkdir -p {}", parent.display()),
            stderr: format!("create_dir_all failed: {e}"),
            exit_code: None,
        })?;
    }

    write_install_file_atomic(
        &config_path,
        out.as_bytes(),
        rewrite_metadata.unwrap_or(AtomicFileMetadata {
            mode: None,
            owner: None,
        }),
    )?;

    Ok(())
}

/// Render the default daemon `config.toml` body — `[daemon]` + `[keyring]`
/// only. This is the single source of the template shared by the install lane
/// ([`write_default_config_if_absent`]) and `ember init`, so the two first-run
/// paths can never drift.
///
/// Per ADR 202, `config.toml` is **system configuration** (socket/data dirs,
/// log level, keyring service/account) — not identity. It carries no Persona,
/// no IdentityRoot, no vault secret; those belong to the first-interactive-use
/// ceremony, not to system provisioning.
pub fn default_config_toml(keyring_service: &str, keyring_account: &str) -> String {
    // Example socket_dir / data_dir comments reflect the ADR 218 system
    // paths the daemon resolves via `DaemonPaths::system()` when these
    // keys are absent. Operators may override under `[daemon]`; the
    // commented examples document the per-OS defaults.
    format!(
        "\
# Ember daemon configuration

[daemon]
# Defaults per ADR 218 (commented; uncomment + edit to override):
# macOS:
#   socket_dir = \"/Library/Application Support/Emberlink/run\"
#   data_dir   = \"/Library/Application Support/Emberlink\"
# Linux:
#   socket_dir = \"/run/ember\"
#   data_dir   = \"/var/lib/ember\"
log_level = \"info\"

[keyring]
service = \"{keyring_service}\"
account = \"{keyring_account}\"
"
    )
}

/// Write the default daemon `config.toml` into the system config dir
/// (`/Library/Application Support/Emberlink/config/` on macOS;
/// `/etc/ember/` on Linux, per [`crate::paths::DaemonPaths::system`]) if
/// it does not already exist.
///
/// Per ADR 218 (2026-06-14) daemon config lives at the system config
/// path, not under any operator's `$HOME`. `operator_home` is retained
/// in the signature for call-site stability across the multi-PR
/// sequence; the parameter is unused.
///
/// The daemon (`emberd`) hard-refuses to boot without this file (see
/// `crates/ember-daemon/src/bin/emberd.rs`), and on a fresh signed-`.pkg`
/// install nothing else creates it: the postinstall runs `ember daemon
/// install` (system provisioning), not `ember init` (the identity ceremony
/// that historically wrote config). That gap left every fresh `.pkg` install
/// failing — the daemon bootstrapped at `emit-launch-spec`, crashed on the
/// missing config, and the install aborted. Per ADR 202 §Decision 2, writing
/// system config is system-provisioning's job, so the install wizard owns it
/// (the `ensure-config` step, sequenced *before* `emit-launch-spec`).
///
/// Idempotent and **non-clobbering**: if a regular `config.toml` already
/// exists it is left untouched — an operator's existing config (hand edits, a
/// prior install's settings, an upgrade-over-existing host) is authoritative.
/// Symlink and non-file config paths are refused rather than followed. The
/// keyring service/account match the daemon-runtime defaults
/// (`EMBER_KEYRING_SERVICE`/`_ACCOUNT` env override → built-in defaults) so the
/// CLI and daemon vault paths agree.
///
/// Ownership: the wizard runs as root and writes the file root-owned;
/// the immediately-following `chown-data-dirs` step walks the daemon's
/// system state root and chowns to `ember:ember-clients`. The system
/// config dir itself is also chowned via that walk (on Linux systemd's
/// `ConfigurationDirectory=ember` covers it).
pub fn write_default_config_if_absent(_operator_home: &Path) -> Result<(), InstallError> {
    write_default_config_if_absent_inner(&crate::paths::DaemonPaths::system())
}

/// Inner helper: factored out so tests can pass `DaemonPaths::for_test(tmp)`
/// and exercise the create-if-absent + non-clobber logic without writing to
/// real system paths.
fn write_default_config_if_absent_inner(
    paths: &crate::paths::DaemonPaths,
) -> Result<(), InstallError> {
    let config_path = paths.config_file();
    if existing_regular_config_metadata(&config_path)?.is_some() {
        return Ok(());
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InstallError::Subprocess {
            cmd: format!("mkdir -p {}", parent.display()),
            stderr: format!("create_dir_all failed: {e}"),
            exit_code: None,
        })?;
    }

    let service = std::env::var("EMBER_KEYRING_SERVICE")
        .unwrap_or_else(|_| crate::infra::vault::DEFAULT_KEYRING_SERVICE.to_string());
    let account = std::env::var("EMBER_KEYRING_ACCOUNT")
        .unwrap_or_else(|_| crate::infra::vault::DEFAULT_KEYRING_ACCOUNT.to_string());

    write_install_file_atomic(
        &config_path,
        default_config_toml(&service, &account).as_bytes(),
        AtomicFileMetadata {
            mode: None,
            owner: None,
        },
    )?;

    Ok(())
}

/// End-to-end macOS spawn-helper provisioning, wired into the install wizard's
/// `provision-spawn-helper` step:
///
/// 1. Provision the per-spawn uid pool (creates the pool's system users).
/// 2. Persist the pool into the daemon's `config.toml` (`[spawn_pool]`) so
///    `broker_exec` can lease a uid.
/// 3. Verify the helper + shim are present at `/usr/local/libexec` (placed by
///    the install lane / `.pkg`), hash the shim, render + bootstrap the
///    `sh.emberlink.spawn-helper` LaunchDaemon.
///
/// Idempotent end-to-end (each step is independently idempotent). Requires
/// root (creates system users, writes `/Library/LaunchDaemons`).
#[cfg(target_os = "macos")]
pub fn provision_spawn_helper_runtime(
    operator_home: &Path,
    pool_size: usize,
) -> Result<(), InstallError> {
    let provisioning = provision_spawn_pool(pool_size)?;
    write_spawn_pool_config(operator_home, &provisioning)?;
    install_spawn_helper_plist(SPAWN_POOL_UID_BASE, pool_size as u32)?;
    Ok(())
}

/// Detect whether the running kernel supports unprivileged user
/// namespace clone (ADR 155 Component 2 modern-Linux gate). Reads
/// `/proc/sys/kernel/unprivileged_userns_clone`. Returns:
///
/// - `Ok(true)` — modern-Linux path: `clone3(CLONE_NEWUSER | ...)`
///   from the `ember` uid will succeed. Installer should provision
///   `/etc/subuid` + `/etc/subgid` entries.
/// - `Ok(false)` — hardened-Linux path: namespace clone is gated to
///   root. Installer should fall through to the system-user pool +
///   sibling spawn-helper daemon (the [`provision_spawn_pool`]
///   path).
/// - `Err(InstallError::Io)` — `/proc/sys/kernel/unprivileged_userns_clone`
///   is missing or unreadable. On non-Linux this is expected
///   (caller filters by `cfg!(target_os = "linux")` before calling).
///
/// ## Why a string parse not `procfs`
///
/// The sysctl file contains a single ASCII digit followed by
/// newline. We avoid adding a procfs dependency for one byte.
pub fn detect_modern_linux_userns() -> Result<bool, InstallError> {
    let path = "/proc/sys/kernel/unprivileged_userns_clone";
    let contents = std::fs::read_to_string(path).map_err(InstallError::Io)?;
    let trimmed = contents.trim();
    match trimmed {
        "1" => Ok(true),
        "0" => Ok(false),
        other => Err(InstallError::Subprocess {
            cmd: format!("read {path}"),
            stderr: format!("unexpected value: {other:?} (want \"0\" or \"1\")"),
            exit_code: None,
        }),
    }
}

/// Outcome of parsing an `/etc/subuid` (or `/etc/subgid`) entry for
/// `ember`. The four variants direct the install path:
///
/// - `None` — no `ember:...` entry exists; safe to append.
/// - `Some(Match { .. })` — exactly one `ember:{start}:{count}` line
///   exists and matches what we would write; no-op (idempotent).
/// - `Some(Conflict { .. })` — exactly one `ember:` line exists with
///   different `(start, count)`; refuse to overwrite. Operator must
///   decide which range is canonical and edit `/etc/subuid` manually.
/// - `Some(MultipleEntries { .. })` — TWO OR MORE `ember:` lines
///   exist (regardless of whether any of them match our desired
///   range). `shadow-utils`' `newuidmap` reads ALL lines for a name
///   and unions the ranges, so a hostile or careless second line
///   can grant authority outside what the daemon expects. We refuse
///   to operate on the file until the operator consolidates.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EmberSubuidEntry {
    /// Existing entry matches the desired `(start, count)` exactly.
    Match,
    /// Existing entry conflicts with the desired range.
    Conflict {
        existing_start: u32,
        existing_count: u32,
    },
    /// Multiple `ember:` entries detected (≥2 lines). Refusal is
    /// defense-in-depth against shadow-utils' "union all ranges for
    /// a name" semantics, which would otherwise let a second line
    /// silently expand the authority the daemon is granted.
    MultipleEntries { count: usize, lines: Vec<String> },
}

/// Scan `/etc/subuid`-shaped content for existing `ember:...:...`
/// entries. Lines are colon-separated triples `name:start:count` per
/// the `shadow-utils` man page; we collect ALL lines where
/// `name == "ember"` because `newuidmap` unions ranges across every
/// matching line for a user.
///
/// Return semantics:
/// - 0 `ember:` lines → `None`
/// - 1 `ember:` line matching `(desired_start, desired_count)` →
///   `Some(Match)`
/// - 1 `ember:` line with different `(start, count)` →
///   `Some(Conflict { existing_start, existing_count })`
/// - ≥2 `ember:` lines → `Some(MultipleEntries { count, lines })`,
///   regardless of any individual line's values (the union of two
///   ranges is structurally ambiguous and we refuse to operate)
///
/// Garbage/comment/blank lines and malformed `ember:` lines (non-
/// numeric start/count) are skipped silently. A malformed line
/// does NOT count toward the multiple-entries threshold.
fn find_ember_subuid_entry(
    contents: &str,
    desired_start: u32,
    desired_count: u32,
) -> Option<EmberSubuidEntry> {
    let mut matched_lines: Vec<(String, u32, u32)> = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let Some(name) = parts.next() else { continue };
        if name != "ember" {
            continue;
        }
        let Some(start_str) = parts.next() else {
            continue;
        };
        let Some(count_str) = parts.next() else {
            continue;
        };
        let Ok(start) = start_str.parse::<u32>() else {
            continue;
        };
        let Ok(count) = count_str.parse::<u32>() else {
            continue;
        };
        matched_lines.push((line.to_string(), start, count));
    }

    match matched_lines.len() {
        0 => None,
        1 => {
            let (_line, start, count) = &matched_lines[0];
            if *start == desired_start && *count == desired_count {
                Some(EmberSubuidEntry::Match)
            } else {
                Some(EmberSubuidEntry::Conflict {
                    existing_start: *start,
                    existing_count: *count,
                })
            }
        }
        n => Some(EmberSubuidEntry::MultipleEntries {
            count: n,
            lines: matched_lines.into_iter().map(|(line, _, _)| line).collect(),
        }),
    }
}

/// Idempotently append `ember:{range_start}:{slot_count}` to the
/// shadow-utils file at `path`. Used for both `/etc/subuid` and
/// `/etc/subgid` (identical line format).
///
/// Returns:
/// - `Ok(true)` — entry was written (file did not previously have
///   an `ember:` line).
/// - `Ok(false)` — entry already existed with matching values
///   (idempotent no-op).
/// - `Err(InstallError::Subprocess { .. })` — a conflicting
///   `ember:{other_start}:{other_count}` already exists; operator
///   must resolve manually. The error message includes both the
///   existing and desired ranges so the operator can decide.
fn ensure_subuid_entry(
    path: &Path,
    range_start: u32,
    slot_count: u32,
) -> Result<bool, InstallError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(InstallError::Io(e)),
    };

    match find_ember_subuid_entry(&contents, range_start, slot_count) {
        Some(EmberSubuidEntry::Match) => Ok(false),
        Some(EmberSubuidEntry::Conflict {
            existing_start,
            existing_count,
        }) => Err(InstallError::Subprocess {
            cmd: format!("ensure_subuid_entry {}", path.display()),
            stderr: format!(
                "refusing to overwrite existing entry: \
                     ember:{existing_start}:{existing_count} already in {} — \
                     desired ember:{range_start}:{slot_count}. Operator must \
                     edit {} manually to resolve.",
                path.display(),
                path.display()
            ),
            exit_code: None,
        }),
        Some(EmberSubuidEntry::MultipleEntries { count, lines }) => {
            // shadow-utils' `newuidmap` reads ALL `ember:` lines and
            // unions their ranges. A second line (whether legacy,
            // misconfiguration, or hostile insertion by an attacker
            // with root) silently expands the authority the daemon is
            // granted past what this installer expects. Refusing for
            // defense-in-depth: operator must consolidate to a single
            // line before the installer will operate on the file.
            Err(InstallError::Subprocess {
                cmd: format!("ensure_subuid_entry {}", path.display()),
                stderr: format!(
                    "refusing to operate on {}: {count} `ember:` lines \
                     detected. shadow-utils unions ALL `ember:` ranges \
                     when newuidmap runs, so a second line silently \
                     expands the authority granted to the daemon. \
                     Operator must consolidate {} to a single ember \
                     line before rerunning install. Existing lines: {:?}",
                    path.display(),
                    path.display(),
                    lines
                ),
                exit_code: None,
            })
        }
        None => {
            // Append (don't rewrite): preserves other entries (other
            // system users, container runtime subuid allocations like
            // dockerd) without disturbing them.
            let mut new_contents = contents.clone();
            if !new_contents.is_empty() && !new_contents.ends_with('\n') {
                new_contents.push('\n');
            }
            new_contents.push_str(&format!("ember:{range_start}:{slot_count}\n"));
            std::fs::write(path, new_contents).map_err(InstallError::Io)?;
            Ok(true)
        }
    }
}

/// ADR 155 Component 2 modern-Linux subuid provisioning. Writes
/// `ember:{SUBUID_RANGE_START}:{SUBUID_RANGE_SLOTS}` to both
/// `/etc/subuid` and `/etc/subgid` so the daemon's clone3-spawn
/// path (CLONE_NEWUSER) can map the range into per-call user
/// namespaces without runtime root.
///
/// **Idempotent.** Detects an existing `ember:` entry via
/// [`find_ember_subuid_entry`]; matching values are a no-op,
/// conflicting values surface a refusal so the operator can
/// resolve manually.
///
/// **Why `usermod` first, file-edit fallback second:**
///
/// `usermod --add-subuids 100000-108191 ember` is the canonical
/// shadow-utils path (locking semantics, audit hooks). However:
///
/// - Older shadow-utils (Debian 10 / RHEL 7) do not implement
///   `--add-subuids`/`--add-subgids`; the flag is rejected.
/// - Some distros symlink `usermod` to a busybox shim that lacks
///   the flag entirely.
/// - The `usermod` path is unprivileged-namespace-aware on modern
///   distros but the file-edit fallback is what `useradd` itself
///   uses internally.
///
/// We try `usermod` first; on flag-not-found we fall back to a
/// direct read-merge-write on `/etc/subuid` + `/etc/subgid`. The
/// direct path produces byte-identical results for the common
/// case.
///
/// Requires elevated privileges (writing `/etc/subuid` +
/// `/etc/subgid` needs root). Typically invoked under `sudo` from
/// the installer entry point.
///
/// ## Output
///
/// On success, returns [`SpawnPoolProvisioning::Subuid`] with the
/// `(range_start, slot_count)` the installer wrote. Caller renders
/// this into the daemon's `[spawn_pool]` config via
/// [`render_spawn_pool_toml`].
#[cfg(target_os = "linux")]
pub fn provision_subuid_range() -> Result<SpawnPoolProvisioning, InstallError> {
    // Install-time probe: refuse install when the setuid newuidmap /
    // newgidmap binaries are missing or not setuid-root. The clone3
    // spawn path invokes them via their absolute canonical paths
    // (`/usr/bin/newuidmap`, `/usr/bin/newgidmap`) and depends on
    // their setuid-root mode to write `/proc/<pid>/uid_map` —
    // installing the daemon on a host without them produces a
    // post-install regression at first-spawn time that's hard to
    // diagnose from the broker_exec stderr alone. Surface it here.
    verify_newuidmap_binary(Path::new("/usr/bin/newuidmap"))?;
    verify_newuidmap_binary(Path::new("/usr/bin/newgidmap"))?;

    provision_subuid_range_at(
        Path::new("/etc/subuid"),
        Path::new("/etc/subgid"),
        SUBUID_RANGE_START,
        SUBUID_RANGE_SLOTS,
    )
}

/// Non-Linux fallback. ADR 155 Component 2 is Linux-only; the
/// modern-Linux subuid range is a Linux kernel concept (unprivileged
/// user namespaces). macOS uses the system-user pool path
/// (Component 3); other platforms are unsupported.
#[cfg(not(target_os = "linux"))]
pub fn provision_subuid_range() -> Result<SpawnPoolProvisioning, InstallError> {
    Err(InstallError::Subprocess {
        cmd: "provision_subuid_range".to_string(),
        stderr: "unsupported platform: subuid range provisioning is Linux-only \
                 (ADR 155 Component 2). macOS uses the system-user pool path."
            .to_string(),
        exit_code: None,
    })
}

/// Testable variant — same logic, caller supplies subuid/subgid
/// paths + the desired range. Production callers use
/// [`provision_subuid_range`] which targets `/etc/subuid` +
/// `/etc/subgid` with [`SUBUID_RANGE_START`] / [`SUBUID_RANGE_SLOTS`].
///
/// **This variant does NOT run the `newuidmap`/`newgidmap` setuid-root
/// install-time probe** so test code can drive it against tempdir-
/// scoped `subuid`/`subgid` files without depending on a real
/// shadow-utils install. Production code paths route through
/// [`provision_subuid_range`] which runs the probe before delegating
/// here. See the `verify_newuidmap_binary` helper (module-private)
/// for the probe rationale.
pub fn provision_subuid_range_at(
    subuid_path: &Path,
    subgid_path: &Path,
    range_start: u32,
    slot_count: u32,
) -> Result<SpawnPoolProvisioning, InstallError> {
    // Try the canonical `usermod` path first if the binary supports
    // the `--add-subuids`/`--add-subgids` flags. We probe by checking
    // help output; if missing, we fall through to the direct file
    // edit which is what `useradd` does internally anyway.
    //
    // The probe is best-effort — any failure (binary missing, help
    // parsing failed, permissions, etc.) falls through to the direct
    // edit. Idempotency is enforced by `ensure_subuid_entry`, not by
    // `usermod`'s own dedup (older `usermod` does not dedup on append).
    let usermod_supports_subuids = usermod_supports_subuid_flags();

    if usermod_supports_subuids {
        // Use `usermod --add-subuids ... ember` + `--add-subgids` when
        // available. Even with `usermod` we still verify the resulting
        // file via `ensure_subuid_entry` to make conflict detection
        // uniform across paths.
        let range_arg = format!("{range_start}-{}", range_start + slot_count - 1);
        let uid_result = run("usermod", &["--add-subuids", &range_arg, "ember"], true);
        let gid_result = run("usermod", &["--add-subgids", &range_arg, "ember"], true);
        // Tolerate failures; fall through to direct edit. The
        // `ensure_subuid_entry` calls below will surface conflicts.
        if let Err(e) = uid_result {
            tracing::debug!(error = ?e, "usermod --add-subuids fell back to direct file edit");
        }
        if let Err(e) = gid_result {
            tracing::debug!(error = ?e, "usermod --add-subgids fell back to direct file edit");
        }
    }

    // Always verify+repair via direct file edit. This is the
    // load-bearing path; `usermod` is purely an optimization for the
    // happy case where shadow-utils is modern enough.
    ensure_subuid_entry(subuid_path, range_start, slot_count)?;
    ensure_subuid_entry(subgid_path, range_start, slot_count)?;

    Ok(SpawnPoolProvisioning::Subuid {
        range_start,
        slot_count,
    })
}

/// Install-time probe for the shadow-utils setuid helpers. Verifies
/// that the binary at `path` exists and is setuid-root — both
/// preconditions for the clone3 spawn path's `newuidmap` /
/// `newgidmap` invocation.
///
/// The clone3 spawn path (`crates/ember-daemon/src/spawn/exec_domain.rs::
/// invoke_idmap_helper`) executes the helper via its absolute canonical
/// path (`/usr/bin/newuidmap` or `/usr/bin/newgidmap`) with
/// `.env_clear()` defense-in-depth. The helper writes
/// `/proc/<child_pid>/uid_map` (or `gid_map`) — that write is gated by
/// CAP_SETUID/CAP_SETGID via the setuid-root mode bit. A missing or
/// non-setuid helper means the spawn path will fail at first invocation
/// with a cryptic `newuidmap: write to uid_map failed: Operation not
/// permitted`; surfacing the refusal at install time gives the operator
/// a clear actionable diagnostic before any agent invocation hits the
/// failure mode.
///
/// Returns an `InstallError::Subprocess` with operator-facing install
/// hints (the package names per distro) when the probe fails.
///
/// Compiled on all unix-family platforms — production callers live in
/// the `#[cfg(target_os = "linux")]` `provision_subuid_range`, but
/// portable tests on macOS / dev hosts must be able to call the probe
/// against tempdir paths to verify the refusal contracts.
#[cfg(any(target_os = "linux", test))]
fn verify_newuidmap_binary(path: &Path) -> Result<(), InstallError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(InstallError::Subprocess {
                cmd: format!("verify_newuidmap_binary {}", path.display()),
                stderr: format!(
                    "shadow-utils helper {} not installed — the modern-Linux \
                     spawn path (ADR 155 Component 2) requires this binary at \
                     its canonical absolute path. Install: \
                     `apt install uidmap` (Debian/Ubuntu) or \
                     `dnf install shadow-utils` (RHEL/Fedora), then rerun \
                     `ember daemon install`.",
                    path.display()
                ),
                exit_code: None,
            });
        }
        Err(e) => return Err(InstallError::Io(e)),
    };

    // Setuid bit (0o4000) AND owner uid 0. The helper must be setuid
    // SO it can write /proc/<pid>/uid_map (which is root-only). A
    // copy of the helper without setuid is functionally broken even
    // if the file exists.
    let mode = metadata.mode();
    let owner_uid = metadata.uid();
    let is_setuid = (mode & 0o4000) != 0;
    let is_root_owned = owner_uid == 0;

    if !is_setuid || !is_root_owned {
        return Err(InstallError::Subprocess {
            cmd: format!("verify_newuidmap_binary {}", path.display()),
            stderr: format!(
                "shadow-utils helper {} is not setuid-root \
                 (mode={mode:o}, owner_uid={owner_uid}; need mode \
                 with 0o4000 set + owner_uid=0). The modern-Linux \
                 spawn path (ADR 155 Component 2) requires setuid \
                 mode because the helper writes /proc/<pid>/uid_map \
                 which is gated by CAP_SETUID. Reinstall the package: \
                 `apt install --reinstall uidmap` (Debian/Ubuntu) or \
                 `dnf reinstall shadow-utils` (RHEL/Fedora).",
                path.display()
            ),
            exit_code: None,
        });
    }

    Ok(())
}

/// Probe whether `usermod` supports `--add-subuids`. Returns `false`
/// on any error (binary missing, exec failed, help output unrecognized)
/// so the caller falls through to the direct file-edit path.
fn usermod_supports_subuid_flags() -> bool {
    let output = match Command::new("usermod").arg("--help").output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    // `--help` exits 0 on most usermod variants; on busybox it may
    // exit non-zero. We don't gate on exit code, only on the help
    // text.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    combined.contains("--add-subuids") || combined.contains("-v, --add-subuids")
}

/// Root-owned directory that holds the GH App credentials the daemon
/// reads at boot. Mode 0750 (root:ember) so only the `ember` uid can
/// list it; world has no access.
const ETC_EMBERLINK_DIR: &str = "/etc/emberlink";

/// Destination path for the GH App PEM inside `/etc/emberlink/`.
const ETC_EMBERLINK_PEM: &str = "/etc/emberlink/ember-engine-app.pem";

/// Destination path for the GH App env file inside `/etc/emberlink/`.
const ETC_EMBERLINK_ENV: &str = "/etc/emberlink/ember-engine.env";

/// Provision `/etc/emberlink/` and copy the GH App PEM + env files from
/// the operator's home into it with mode `0440` owned `root:ember`.
///
/// **Idempotent.** Each install re-applies mode and ownership so operator-
/// side chmod drift is corrected automatically. If the source PEM does not
/// exist (operator hasn't set up the GH App yet) the function returns
/// `Ok(())` without erroring.
///
/// Steps:
/// 1. Create `/etc/emberlink/` with mode `0750`, owned `root:ember`.
/// 2. Copy `<operator_home>/.config/emberlink/ember-engine-app.pem` →
///    `/etc/emberlink/ember-engine-app.pem` (skip if source missing).
/// 3. Copy `<operator_home>/.config/emberlink/ember-engine.env` →
///    `/etc/emberlink/ember-engine.env` (skip if source missing).
/// 4. Re-apply `chown root:ember-clients` + `chmod 0440` on each destination
///    file so mode/ownership converge even when the file was already present.
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point).
pub fn install_pem_to_etc(operator_home: &Path) -> Result<(), InstallError> {
    // 1) Provision /etc/emberlink/ — idempotent: mkdir -p tolerates existing.
    run("mkdir", &["-p", ETC_EMBERLINK_DIR], false)?;
    run("chmod", &["0750", ETC_EMBERLINK_DIR], false)?;
    run("chown", &["root:ember-clients", ETC_EMBERLINK_DIR], false)?;

    let src_config = operator_home.join(".config").join("emberlink");

    // 2 & 3) Copy each credential file; skip gracefully when source is absent.
    for (src_name, dst_path) in &[
        ("ember-engine-app.pem", ETC_EMBERLINK_PEM),
        ("ember-engine.env", ETC_EMBERLINK_ENV),
    ] {
        let src = src_config.join(src_name);
        if !src.exists() {
            tracing::debug!(src = %src.display(), "GH App credential not found — skipping");
            continue;
        }

        copy_root_credential_file_atomic(&src, Path::new(dst_path))?;
        run("chmod", &["0440", dst_path], false)?;
        // `root:ember-clients` (formerly `root:ember`) so the daemon — running
        // with `ember-clients` as primary group per the matching plist change
        // in `render_launchd_plist_body` — can read the credential.
        run("chown", &["root:ember-clients", dst_path], false)?;
    }

    Ok(())
}

/// Parent directory of the `emberd` install path (`/usr/local/bin/emberd`).
/// `mkdir -p` covers the rare case where `/usr/local/` exists without
/// `/usr/local/bin/` (fresh user directories on some macOS images, minimal
/// Linux base images).
const EMBERD_INSTALL_DIR: &str = "/usr/local/bin";
const MANAGED_EMBERD_PATH: &str = "/usr/local/bin/emberd";

/// Env-var override naming an explicit path to the `emberd` binary that
/// install should publish. Honored when non-empty and free of `..` segments.
/// Set this in CI / package builds where the binary lives outside
/// `<cwd>/target/release/`.
const ENV_EMBERD_BIN_PATH: &str = "EMBER_EMBERD_BIN_PATH";

/// Installed name of the `emberd-rpc` mTLS-frontend sibling binary
/// (ADR 155 amendment). Platform-specific because the two `[[bin]]`
/// targets in `ember-rpc`'s `Cargo.toml` are `emberd-rpc-macos` and
/// `emberd-rpc-linux` (they share one `main.rs`; the split exists so each
/// platform unit references a concrete binary name). Source of truth:
/// `crate::install_manifest::INSTALL_ARTIFACTS` (`bin: "emberd-rpc-macos"`
/// / `"emberd-rpc-linux"`).
#[cfg(target_os = "macos")]
const EMBERD_RPC_BIN_NAME: &str = "emberd-rpc-macos";
#[cfg(target_os = "linux")]
const EMBERD_RPC_BIN_NAME: &str = "emberd-rpc-linux";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const EMBERD_RPC_BIN_NAME: &str = "emberd-rpc-linux";

/// Env-var override naming an explicit path to the `emberd-rpc` sibling
/// binary to publish. Same contract as [`ENV_EMBERD_BIN_PATH`]: non-empty,
/// `..`-free, must exist. Set this in CI / package builds where the binary
/// lives outside `<cwd>/target/release/`.
const ENV_EMBERD_RPC_BIN_PATH: &str = "EMBER_EMBERD_RPC_BIN_PATH";

/// Resolve the `emberd` source binary to publish.
///
/// Resolution order:
/// 1. `EMBER_EMBERD_BIN_PATH` env var (non-empty, no `..` segments) —
///    authoritative override. Errors when set but the path does not exist.
/// 2. Sibling of `current_exe()` named `emberd`. `current_exe()` is
///    canonicalized first so a symlinked launcher (`~/.cargo/bin/ember -> target/release/ember`)
///    resolves to the real workspace dir where `emberd` was built alongside.
/// 3. Installed macOS app-bundle layout: when the launcher is
///    `/usr/local/lib/ember.app/Contents/MacOS/ember`, use the managed daemon
///    at `/usr/local/bin/emberd` (normally a symlink into `emberd.app`).
///
/// Errors with a copy-pasteable build hint when neither path resolves —
/// operators see "build `emberd` first with `cargo build --release -p
/// ember-daemon --bin emberd`, or set EMBER_EMBERD_BIN_PATH".
pub fn resolve_emberd_source() -> Result<PathBuf, InstallError> {
    if let Ok(raw) = std::env::var(ENV_EMBERD_BIN_PATH)
        && !raw.is_empty()
    {
        let path = PathBuf::from(&raw);
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(InstallError::Subprocess {
                cmd: "resolve_emberd_source".to_string(),
                stderr: format!("{ENV_EMBERD_BIN_PATH}={raw:?} contains `..` segment — refused"),
                exit_code: None,
            });
        }
        if !path.exists() {
            return Err(InstallError::Subprocess {
                cmd: "resolve_emberd_source".to_string(),
                stderr: format!("{ENV_EMBERD_BIN_PATH}={raw:?} does not exist"),
                exit_code: None,
            });
        }
        return Ok(path);
    }

    let current = std::env::current_exe().map_err(|e| InstallError::Subprocess {
        cmd: "current_exe".to_string(),
        stderr: format!("could not resolve current_exe: {e}"),
        exit_code: None,
    })?;
    let canonical = current.canonicalize().unwrap_or(current.clone());
    resolve_emberd_source_from_current_exe(&canonical, Path::new(MANAGED_EMBERD_PATH))
}

fn resolve_emberd_source_from_current_exe(
    current_exe: &Path,
    managed_emberd_path: &Path,
) -> Result<PathBuf, InstallError> {
    let parent = current_exe
        .parent()
        .ok_or_else(|| InstallError::Subprocess {
            cmd: "resolve_emberd_source".to_string(),
            stderr: format!("current_exe has no parent: {}", current_exe.display()),
            exit_code: None,
        })?;
    let sibling = parent.join("emberd");
    if sibling.exists() {
        return Ok(sibling);
    }

    if is_macos_ember_app_launcher(current_exe) && managed_emberd_path.exists() {
        return Ok(managed_emberd_path.to_path_buf());
    }

    Err(InstallError::Subprocess {
        cmd: "resolve_emberd_source".to_string(),
        stderr: format!(
            "could not find `emberd` next to {}. Build with \
             `cargo build --release -p ember-daemon --bin emberd`, \
             install the managed host daemon at {MANAGED_EMBERD_PATH}, \
             or set {ENV_EMBERD_BIN_PATH} to an absolute path.",
            current_exe.display()
        ),
        exit_code: None,
    })
}

fn is_macos_ember_app_launcher(path: &Path) -> bool {
    if path.file_name().and_then(|s| s.to_str()) != Some("ember") {
        return false;
    }
    let Some(macos_dir) = path.parent() else {
        return false;
    };
    if macos_dir.file_name().and_then(|s| s.to_str()) != Some("MacOS") {
        return false;
    }
    let Some(contents_dir) = macos_dir.parent() else {
        return false;
    };
    if contents_dir.file_name().and_then(|s| s.to_str()) != Some("Contents") {
        return false;
    }
    let Some(app_dir) = contents_dir.parent() else {
        return false;
    };
    app_dir.file_name().and_then(|s| s.to_str()) == Some("ember.app")
}

/// Publish the `emberd` daemon binary to `/usr/local/bin/emberd` so the
/// LaunchDaemon (macOS) / systemd unit (Linux) can exec it.
///
/// **Idempotent + safe under a running daemon.** If `/usr/local/bin/emberd`
/// already exists it is `unlink`-ed before the copy: the old inode persists
/// for any process still holding it open (running ember-daemon keeps using
/// the in-memory image), the new copy creates a fresh inode, and the next
/// `launchctl bootout`/`bootstrap` (or `systemctl restart`) picks up the
/// fresh file. On Linux this avoids `ETXTBSY` when the daemon is currently
/// running; on macOS the cycle works without unlink but we do it for
/// consistency.
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point) — `/usr/local/bin/` and the `chown root:*` need
/// root.
pub fn install_emberd_binary() -> Result<(), InstallError> {
    let src = resolve_emberd_source()?;
    install_emberd_binary_at(&src, Path::new(EMBERD_INSTALL_DIR), "emberd")
}

/// Testable variant — same logic, caller supplies destination dir +
/// filename so tests can use a tempdir without sudo. Production callers
/// use [`install_emberd_binary`] which targets `/usr/local/bin/emberd`.
///
/// The `dst_name` parameter exists so the test for "src already at dst"
/// doesn't need to be at `/usr/local/bin/emberd`; production always passes
/// `"emberd"`.
pub fn install_emberd_binary_at(
    src: &Path,
    dst_dir: &Path,
    dst_name: &str,
) -> Result<(), InstallError> {
    // mkdir -p dst_dir — tolerates pre-existing.
    std::fs::create_dir_all(dst_dir).map_err(|e| InstallError::Subprocess {
        cmd: format!("mkdir -p {}", dst_dir.display()),
        stderr: format!("create_dir_all failed: {e}"),
        exit_code: None,
    })?;

    let dst = dst_dir.join(dst_name);
    let dst_str = dst.to_string_lossy().into_owned();
    let src_str = src.to_string_lossy().into_owned();

    // No-op if src and dst already resolve to the same canonical path —
    // re-running install when `current_exe` already IS the installed
    // emberd is a corner case (operator runs `sudo /usr/local/bin/ember
    // daemon install` from a host where the install previously
    // succeeded). Skipping the unlink avoids the brief gap where the
    // file disappears.
    if let (Ok(sc), Ok(dc)) = (src.canonicalize(), dst.canonicalize())
        && sc == dc
    {
        // Still re-apply mode + ownership so they converge if they
        // drifted (operator manually chmod-ed the file).
        run("chmod", &["0755", &dst_str], false)?;
        chown_emberd_binary(&dst_str)?;
        return Ok(());
    }

    // Remove existing dst (unlinks inode; running process keeps fd to
    // old inode). Tolerate "does not exist".
    if dst.exists() {
        std::fs::remove_file(&dst).map_err(|e| InstallError::Subprocess {
            cmd: format!("remove {dst_str}"),
            stderr: format!("remove failed: {e}"),
            exit_code: None,
        })?;
    }

    // Copy fresh inode into place.
    std::fs::copy(src, &dst).map_err(|e| InstallError::Subprocess {
        cmd: format!("copy {src_str} -> {dst_str}"),
        stderr: format!("copy failed: {e}"),
        exit_code: None,
    })?;

    run("chmod", &["0755", &dst_str], false)?;
    chown_emberd_binary(&dst_str)?;

    Ok(())
}

/// Apply the platform-appropriate ownership to the published binary.
/// macOS uses `root:wheel` (Apple convention for system binaries);
/// Linux uses `root:root`.
fn chown_emberd_binary(dst_str: &str) -> Result<(), InstallError> {
    #[cfg(target_os = "macos")]
    let owner = "root:wheel";
    #[cfg(target_os = "linux")]
    let owner = "root:root";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let owner = "root:root";

    // The macOS package install publishes /usr/local/bin/emberd as a symlink
    // into emberd.app. Plain chown follows the link and may fail on the
    // package-owned app bundle; the LaunchDaemon only needs the launcher path
    // ownership converged, so operate on the symlink itself.
    #[cfg(target_os = "macos")]
    return run("chown", &["-h", owner, dst_str], false);

    #[cfg(not(target_os = "macos"))]
    run("chown", &[owner, dst_str], false)
}

// ============================================================================
// ADR 155 bridge priv-sep SLICE 2b — emberd-rpc sibling bootstrap.
//
// ember_rpc_sibling_bootstrap_landed
//
// The `emberd-rpc` mTLS-frontend sibling (ADR 155 amendment, listener wired
// post-SLICE-2a #5349) is built + manifest-declared but, before this slice,
// the install lane never staged or supervised it. This block:
//   1. publishes the platform binary to /usr/local/bin (install_emberd_rpc_binary),
//   2. renders the launchd/systemd unit with daemon system-path cert/socket
//      pins (render_rpc_{launchd_plist,systemd_unit}_body),
//   3. always stages the unit, and conditionally bootstraps it — only when the
//      bridge lane is configured ON (rpc_sibling_should_bootstrap), matching the
//      "inert until enabled" doctrine (the rpc server cert + bridge_ca are minted
//      by emberd core ONLY when `bridge_bind` is set — runtime.rs:1392/4001; a
//      bridge-OFF bootstrap would restart-loop on the absent cert).
//
// CRITICAL path pins (see the four env vars below): the prod daemon resolves
// `socket_dir` + `data_dir` via `DaemonPaths::system()` (ADR 218), NOT the
// sibling default config and NOT any operator-home `.ember` path. So the units
// MUST pin daemon system paths, rendered in Rust.
// ============================================================================

/// Resolve the platform `emberd-rpc` sibling source binary to publish.
///
/// Mirrors [`resolve_emberd_source`] exactly:
///   1. `EMBER_EMBERD_RPC_BIN_PATH` env override (non-empty, no `..`, must exist).
///   2. Sibling of `current_exe()` named [`EMBERD_RPC_BIN_NAME`]
///      (`emberd-rpc-{macos,linux}`).
///   3. Installed managed path (`/usr/local/bin/emberd-rpc-{macos,linux}`) when the
///      launcher is the macOS app-bundle layout.
pub fn resolve_emberd_rpc_source() -> Result<PathBuf, InstallError> {
    if let Ok(raw) = std::env::var(ENV_EMBERD_RPC_BIN_PATH)
        && !raw.is_empty()
    {
        let path = PathBuf::from(&raw);
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(InstallError::Subprocess {
                cmd: "resolve_emberd_rpc_source".to_string(),
                stderr: format!(
                    "{ENV_EMBERD_RPC_BIN_PATH}={raw:?} contains `..` segment — refused"
                ),
                exit_code: None,
            });
        }
        if !path.exists() {
            return Err(InstallError::Subprocess {
                cmd: "resolve_emberd_rpc_source".to_string(),
                stderr: format!("{ENV_EMBERD_RPC_BIN_PATH}={raw:?} does not exist"),
                exit_code: None,
            });
        }
        return Ok(path);
    }

    let current = std::env::current_exe().map_err(|e| InstallError::Subprocess {
        cmd: "current_exe".to_string(),
        stderr: format!("could not resolve current_exe: {e}"),
        exit_code: None,
    })?;
    let canonical = current.canonicalize().unwrap_or(current.clone());
    let managed = format!("/usr/local/bin/{EMBERD_RPC_BIN_NAME}");
    resolve_emberd_rpc_source_from_current_exe(&canonical, Path::new(&managed))
}

fn resolve_emberd_rpc_source_from_current_exe(
    current_exe: &Path,
    managed_rpc_path: &Path,
) -> Result<PathBuf, InstallError> {
    let parent = current_exe
        .parent()
        .ok_or_else(|| InstallError::Subprocess {
            cmd: "resolve_emberd_rpc_source".to_string(),
            stderr: format!("current_exe has no parent: {}", current_exe.display()),
            exit_code: None,
        })?;
    let sibling = parent.join(EMBERD_RPC_BIN_NAME);
    if sibling.exists() {
        return Ok(sibling);
    }

    if is_macos_ember_app_launcher(current_exe) && managed_rpc_path.exists() {
        return Ok(managed_rpc_path.to_path_buf());
    }

    Err(InstallError::Subprocess {
        cmd: "resolve_emberd_rpc_source".to_string(),
        stderr: format!(
            "could not find `{EMBERD_RPC_BIN_NAME}` next to {}. Build with \
             `cargo build --release -p ember-rpc`, install the managed sibling \
             at {}, or set {ENV_EMBERD_RPC_BIN_PATH} to an absolute path.",
            current_exe.display(),
            managed_rpc_path.display()
        ),
        exit_code: None,
    })
}

/// Publish the `emberd-rpc` sibling binary to
/// `/usr/local/bin/emberd-rpc-{macos,linux}` so the launchd/systemd unit can
/// exec it. Idempotent + safe under a running sibling (unlink-then-copy →
/// fresh inode; the running process keeps its fd to the old inode). Mirrors
/// [`install_emberd_binary`].
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point).
pub fn install_emberd_rpc_binary() -> Result<(), InstallError> {
    let src = resolve_emberd_rpc_source()?;
    install_emberd_rpc_binary_at(&src, Path::new(EMBERD_INSTALL_DIR), EMBERD_RPC_BIN_NAME)
}

/// Testable variant of [`install_emberd_rpc_binary`] — caller supplies the
/// destination dir + filename so tests run in a tempdir without sudo.
/// Production callers use [`install_emberd_rpc_binary`].
pub fn install_emberd_rpc_binary_at(
    src: &Path,
    dst_dir: &Path,
    dst_name: &str,
) -> Result<(), InstallError> {
    std::fs::create_dir_all(dst_dir).map_err(|e| InstallError::Subprocess {
        cmd: format!("mkdir -p {}", dst_dir.display()),
        stderr: format!("create_dir_all failed: {e}"),
        exit_code: None,
    })?;

    let dst = dst_dir.join(dst_name);
    let dst_str = dst.to_string_lossy().into_owned();
    let src_str = src.to_string_lossy().into_owned();

    // No-op if src and dst already resolve to the same canonical path.
    if let (Ok(sc), Ok(dc)) = (src.canonicalize(), dst.canonicalize())
        && sc == dc
    {
        run("chmod", &["0755", &dst_str], false)?;
        chown_emberd_binary(&dst_str)?;
        return Ok(());
    }

    // Remove existing dst (unlinks inode; running process keeps fd to old
    // inode). Tolerate "does not exist".
    if dst.exists() {
        std::fs::remove_file(&dst).map_err(|e| InstallError::Subprocess {
            cmd: format!("remove {dst_str}"),
            stderr: format!("remove failed: {e}"),
            exit_code: None,
        })?;
    }

    std::fs::copy(src, &dst).map_err(|e| InstallError::Subprocess {
        cmd: format!("copy {src_str} -> {dst_str}"),
        stderr: format!("copy failed: {e}"),
        exit_code: None,
    })?;

    run("chmod", &["0755", &dst_str], false)?;
    chown_emberd_binary(&dst_str)?;

    Ok(())
}

/// Decide whether the install lane should actively bootstrap the `emberd-rpc`
/// sibling, versus only stage it.
///
/// "Option A" lifecycle (ADR 155 SLICE 2b): the sibling is bootstrapped ONLY
/// when the bridge lane is configured ON at install time, because the rpc
/// server cert + `bridge_ca.pem` are minted by emberd core exclusively inside
/// its `if let Some(bridge_bind)` startup branch (runtime.rs:1392 →
/// `mint_or_rotate_ember_rpc_server_cert`). A bridge-OFF host has no cert on
/// disk; the sibling exits when its cert is absent and `KeepAlive`/`Restart`
/// would turn that into a restart loop. Staging-without-bootstrap keeps the
/// whole lane genuinely inert until the operator enables the bridge — the same
/// posture the daemon's own 0700 rpc receiver uses (runtime.rs:3781, gated on
/// `bridge_bind.is_some()`).
///
/// Resolution: SOLELY the persisted system `config.toml`
/// (`DaemonPaths::system().config_file()` per ADR 218) `[daemon].bridge_bind`
/// value — the ONLY bridge signal the launchd/systemd-launched daemon
/// actually honors at runtime.
///
/// `EMBER_BRIDGE_BIND` in the INSTALLER's process env is deliberately NOT
/// consulted. The daemon's own unit (`render_launchd_plist_body_*` /
/// `render_systemd_unit_body`) bakes only EMBER_APP_* (+ trust roots) —
/// HOME is no longer baked per ADR 218 — and the installer never persists
/// that env into config. So an installer-env value the daemon can't see
/// would bootstrap a sibling while the daemon boots bridge-OFF, never mints
/// the rpc cert, and crash-loops the sibling — the exact silent failure
/// SLICE 2b exists to prevent. Gating on config.toml keeps the install-time
/// decision and the daemon's runtime decision reading the SAME source of
/// truth. (Hardened after adversarial review, 2026-06-05.)
///
///   * `[daemon].bridge_bind` non-empty AND parses as a `SocketAddr` ⇒ ON.
///   * empty / absent / malformed / no config file ⇒ OFF (bridge disabled).
///
/// A malformed value resolves to OFF: a non-parseable `bridge_bind` is a hard
/// daemon-startup abort (config.rs validation), so we must NOT bootstrap a
/// sibling for a daemon that will refuse to boot.
///
/// `operator_home` retained for call-site stability across the multi-PR
/// sequence; the parameter is unused (config now lives at the system path).
pub fn rpc_sibling_should_bootstrap(_operator_home: &Path) -> bool {
    rpc_sibling_should_bootstrap_inner(&crate::paths::DaemonPaths::system())
}

/// Inner: read the config from `paths.config_file()` so tests can swap
/// in a `for_test` tempdir.
fn rpc_sibling_should_bootstrap_inner(paths: &crate::paths::DaemonPaths) -> bool {
    // Read the raw config string (not the full DaemonConfig) so this helper has
    // no dependency on the loader's side effects — it must be callable under
    // sudo without touching the vault.
    let config_path = paths.config_file();
    let Ok(contents) = std::fs::read_to_string(&config_path) else {
        return false; // no config file ⇒ bridge disabled by default
    };
    bridge_bind_value_is_set(&contents)
}

/// Parse the `[daemon].bridge_bind` value out of a `config.toml` body and
/// report whether it is set to a non-empty, `SocketAddr`-parseable string.
/// Returns false when the key is absent, the value is empty, the value does not
/// parse as a `SocketAddr` (a malformed `bridge_bind` is a hard daemon-startup
/// abort, so it is NOT "bridge on" for bootstrap purposes), or the TOML can't
/// be parsed.
///
/// Factored out so a test can exercise the parse without writing a temp file
/// and without depending on the full `DaemonConfig` loader. The `SocketAddr`
/// parse matches the daemon's own `bridge_bind: Option<SocketAddr>` resolution
/// (config.rs), so this cannot under-bootstrap a value the daemon would accept.
fn bridge_bind_value_is_set(config_toml: &str) -> bool {
    // Use `toml::from_str` (the proven call shape elsewhere in this module);
    // toml 1.0's `FromStr for Value` does not always accept a full document.
    let Ok(value) = toml::from_str::<toml::Value>(config_toml) else {
        return false;
    };
    value
        .get("daemon")
        .and_then(|d| d.get("bridge_bind"))
        .and_then(|b| b.as_str())
        .map(|s| !s.is_empty() && s.parse::<std::net::SocketAddr>().is_ok())
        .unwrap_or(false)
}

/// Recursively chown every entry under the daemon's system state root
/// (`/Library/Application Support/Emberlink/` on macOS;
/// `/var/lib/ember/` on Linux per [`crate::paths::DaemonPaths::system`])
/// to `ember:ember-clients` and tighten file modes.
///
/// Per ADR 218 (operator-locked 2026-06-14) the daemon's at-rest state
/// lives at system paths, not under any operator's `$HOME`. The `home`
/// parameter is retained for call-site stability across the multi-PR
/// sequence — PR 3e/3f sweep the CLI callers that pass it. The
/// parameter is unused; the chown walk targets [`DaemonPaths::system`]
/// (`crate::paths::DaemonPaths::system`).
///
/// **Why this walks the whole state tree instead of a hardcoded subdir
/// list:** the daemon's `DaemonConfig::load_defaults` populates
/// `data_dir`, `socket_dir`, `pid_file`, `policy_file` from
/// `DaemonPaths::system()`. The set of subdirectories the daemon
/// creates (vault, grants, sessions, codex-sessions, locks, etc.) is
/// runtime-driven, not install-driven. Walking the state root keeps
/// chown coverage tracking whatever the daemon actually creates,
/// without requiring a parallel update here.
///
/// **Idempotent.** The state root or any subdirectory may be absent on
/// the first install; those cases are skipped silently so re-running on
/// an already-correct tree is a no-op.
///
/// For each entry walked:
/// - `chown ember:ember-clients <path>`
/// - directories: `chmod 0750 <path>`
/// - signing-key files (`*.key`): `chmod 0600 <path>` (owner-only)
/// - other files: `chmod 0640 <path>`
///
/// Requires elevated privileges (typically invoked under `sudo` from
/// the installer entry point).
///
pub fn chown_ember_data_dirs(_home: &Path) -> Result<(), InstallError> {
    // Daemon-side state — the post-ADR-218 system root.
    let paths = crate::paths::DaemonPaths::system();
    chown_ember_data_dirs_inner(&paths.state_root, &mut |path, is_dir| {
        let path_str = path.to_string_lossy().into_owned();
        run("chown", &["ember:ember-clients", &path_str], false)?;
        // Signing-key material (daemon_identity.key, daemon_persona.key)
        // must be 0600 (owner-only) per the daemon's fail-closed check
        // in `infra::runtime` (audit-chain startup wiring).
        // The default 0640 lets the ember-clients group read non-secret
        // state (SQLite, snapshots, vault.salt, etc.) but is too
        // permissive for private keys.
        let is_private_key = !is_dir && (path.extension().and_then(|s| s.to_str()) == Some("key"));
        let mode = if is_dir {
            "0750"
        } else if is_private_key {
            "0600"
        } else {
            "0640"
        };
        run("chmod", &[mode, &path_str], false)
    })
}

/// Inner logic for [`chown_ember_data_dirs`], factored out so tests can
/// inject a mock chown closure without needing root privileges or a real
/// `ember` system user.
///
/// `state_root` is the daemon's at-rest data root — production callers
/// pass [`DaemonPaths::system().state_root`]; tests pass a tempdir.
/// `apply_ownership` receives `(path, is_dir)` for every entry visited
/// and is responsible for chown + chmod. Production injects the real
/// `run("chown", ...)` / `run("chmod", ...)` shell-outs; tests inject a
/// closure that records which paths were visited.
///
/// Per ADR 218 the legacy operator-owned exceptions
/// (`orchestrator.lock`, `shadow/`, `binaries/`) no longer apply — those
/// subtrees were the operator-side bleed of the pre-split `~/.ember/`
/// layout and now live at the operator-conventional cache/data paths.
/// The system state root contains ONLY daemon-owned state, so the walk
/// is unconditional.
fn chown_ember_data_dirs_inner<F>(
    state_root: &Path,
    apply_ownership: &mut F,
) -> Result<(), InstallError>
where
    F: FnMut(&Path, bool) -> Result<(), InstallError>,
{
    if !state_root.exists() {
        // Nothing to chown — installer has not created the state tree yet.
        return Ok(());
    }

    // Walk every entry under the state root and chown each recursively.
    // The state root itself is also chowned so the root dir is
    // `ember:ember-clients` mode 0750 (the kernel uses dir traverse-only
    // rights for the `ember-clients` group to reach the socket).
    let root_meta = std::fs::symlink_metadata(state_root)?;
    if root_meta.file_type().is_dir() {
        apply_ownership(state_root, true)?;
        for entry in std::fs::read_dir(state_root)? {
            let entry = entry?;
            chown_chmod_recursive_inner(&entry.path(), apply_ownership)?;
        }
    }

    Ok(())
}

/// Recursive helper: visit `path` and (if a directory) every descendant,
/// calling `apply_ownership(path, is_dir)` for each.
fn chown_chmod_recursive_inner<F>(path: &Path, apply_ownership: &mut F) -> Result<(), InstallError>
where
    F: FnMut(&Path, bool) -> Result<(), InstallError>,
{
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        // Shadow shims under ~/.ember/shadow are symlinks into operator-owned
        // tool wrappers. Some can be intentionally absent on a host, so
        // following them via plain chown/chmod would fail on dangling targets.
        // The daemon does not rely on symlink ownership here; skip them.
        return Ok(());
    }
    let is_dir = metadata.is_dir();

    // chown applies to the current entry (symlinks are not followed; the
    // target inode is chowned directly when we encounter it in the walk).
    apply_ownership(path, is_dir)?;

    if is_dir && !metadata.file_type().is_symlink() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            chown_chmod_recursive_inner(&entry.path(), apply_ownership)?;
        }
    }

    Ok(())
}

/// Filename for the SE-wrapped vault MEK blob under the daemon's data dir.
// security/vault constant retained for callers; allow over delete in lint-clear.
#[allow(dead_code)]
const VAULT_MEK_FILENAME: &str = "vault-mek.bin";

/// Provision the vault MEK passphrase in `/Library/Keychains/System.keychain`
/// and prepare `<home>/.ember/data/` for the daemon's other at-rest state.
///
/// Per **Plan 2A** (System.keychain generic-password storage, see
/// `infra::vault_macos_se`), the MEK is stored as a
/// `kSecClassGenericPassword` item under service
/// [`VAULT_MEK_SERVICE`] / account [`VAULT_MEK_ACCOUNT`] with a permissive
/// partition list (`security add-generic-password -A`). Install (root)
/// writes the item; daemon (ember via launchd) reads it via `securityd`
/// brokering.
///
/// ## Why we landed on Plan 2A
///
/// Two earlier attempts to preserve SE hardware binding for the MEK
/// failed against macOS's API surface:
///
/// 1. **SE key in DPK with install fork+exec to ember uid**: cross-uid
///    DPK access works for normal apps but NOT across the sudo-spawned
///    install child vs launchd-spawned daemon contexts. Different Mach
///    bootstrap ports → different DPK partitions for system uids.
///    Daemon got `errSecItemNotFound`.
/// 2. **Daemon self-provisions SE key at first boot (Plan J)**: the
///    launchd-spawned daemon's context returns `OSStatus -25291
///    errSecNotAvailable` ("No keychain is available") on
///    `SecKeyCreateRandomKey` with permanence. The daemon has no
///    keychain it can write SE-key metadata to.
///
/// Conclusion: SE binding for *persistent* secrets in a separate-uid
/// headless launchd daemon is not supported on macOS. Plan 2A drops SE
/// binding and uses Apple's canonical pattern for system-daemon-shared
/// credentials (`apsd`, `mDNSResponder`, `cfprefsd`). Plan 2D — a future
/// follow-up — restores SE binding via a cross-uid helper running in
/// the operator's GUI session.
///
/// ## Threat model delta vs the abandoned SE approach
///
/// - Lost: MEK hardware binding. Root with `security
///   find-generic-password -a vault-mek -s sh.emberlink.daemon -w
///   /Library/Keychains/System.keychain` CAN extract the MEK plaintext.
///   This is documented in the dev0 threat model.
/// - Kept: vault data is XChaCha20-Poly1305 under MEK; the daemon's
///   grant + receipt machinery; separate-uid posture (ADR 131); the
///   first-per-session Touch-ID gate at the higher vault layer.
///
/// ## Steps
///
/// 1. `mkdir -p <home>/.ember/data/` and chown to `ember:ember-clients`
///    so the daemon (running as ember via launchd) can write its
///    SQLite state, snapshot files, etc.
/// 2. Delete any orphaned `vault-mek.bin` (legacy SE-wrapped blob from
///    earlier install attempts — no longer used).
/// 3. On macOS + root: write the MEK passphrase to System.keychain via
///    `security add-generic-password -A`, idempotent on item presence.
///
/// **Idempotent.** If the MEK item already exists in System.keychain,
/// the function skips re-provisioning to avoid destroying access to
/// existing vault data encrypted under the previous MEK.
///
/// ## Known follow-up
///
/// The shell-out to
/// `/usr/bin/security` passes the passphrase in `argv` for the duration
/// of the subprocess (~50ms on a single-user dev box). Long-term fix is
/// raw FFI to `SecKeychainAddGenericPassword` + `SecAccessCreate` with
/// an explicit permissive ACL, which avoids the argv leak entirely.
///
/// The daemon now self-provisions its SE key at startup — install only
/// needs to ensure the data directory exists with correct ownership.
/// System.keychain passphrase provisioning is retired (SE custody).
pub fn provision_se_mek(_home: &Path) -> Result<(), InstallError> {
    // ADR 218: daemon at-rest state (including `vault-mek.bin` and the
    // sealed-blob directory) lives at the system data dir, NOT under
    // any operator's `$HOME`. Resolve via `DaemonPaths::system()`. The
    // `_home` parameter is retained for call-site stability across
    // the multi-PR sequence; it is unused.
    provision_se_mek_inner(&crate::paths::DaemonPaths::system())
}

/// Inner provisioning helper: factored out so unit tests can pass a
/// `DaemonPaths::for_test(tmp)` instance and exercise the create/clean-up
/// logic without writing to real system paths.
fn provision_se_mek_inner(paths: &crate::paths::DaemonPaths) -> Result<(), InstallError> {
    let data_dir = &paths.data_dir;

    std::fs::create_dir_all(data_dir).map_err(|e| InstallError::Subprocess {
        cmd: format!("mkdir -p {}", data_dir.display()),
        stderr: format!("create_dir_all failed: {e}"),
        exit_code: None,
    })?;

    #[cfg(target_os = "macos")]
    if nix::unistd::geteuid().is_root() {
        let s = data_dir.to_string_lossy().into_owned();
        run("chown", &["ember:ember-clients", &s], false)?;
        run("chmod", &["0750", &s], false)?;
    }

    // Delete legacy artifacts from previous install approaches.
    for name in ["vault-mek.bin", ".vault-mek-provision-failed"] {
        let path = data_dir.join(name);
        if path.exists()
            && let Err(e) = std::fs::remove_file(&path)
        {
            tracing::warn!(path = %path.display(), error = %e, "could not delete legacy file; proceeding");
        }
    }

    // Delete legacy System.keychain passphrase if present (clean break).
    #[cfg(target_os = "macos")]
    if nix::unistd::geteuid().is_root() {
        delete_legacy_system_keychain_passphrase();
    }

    Ok(())
}

/// Best-effort delete the legacy System.keychain MEK passphrase item
/// left by previous installs. Non-fatal — the daemon no longer reads it.
#[cfg(target_os = "macos")]
fn delete_legacy_system_keychain_passphrase() {
    use security_framework::os::macos::keychain::SecKeychain;

    const SERVICE: &str = "sh.emberlink.daemon";
    const ACCOUNT: &str = "vault-mek";
    const PATH: &str = "/Library/Keychains/System.keychain";

    let Ok(keychain) = SecKeychain::open(PATH) else {
        return;
    };
    if let Ok((_pw, item)) = keychain.find_generic_password(SERVICE, ACCOUNT) {
        item.delete();
        tracing::info!("deleted legacy vault-mek passphrase from System.keychain (SE custody)");
    }
}

// Plist + systemd unit bodies historically baked the operator's HOME into
// the launcher's `EnvironmentVariables` / `Environment=` block so the
// daemon (running as the `ember` system uid) could resolve `~/.ember/...`
// to the operator's chowned-to-ember data tree. Per ADR 218 (operator-
// locked 2026-06-14) the daemon's at-rest state + runtime socket + pid +
// config now live at OS system paths (`/Library/Application Support/
// Emberlink/` on macOS; `/var/lib/ember/` + `/run/ember/` + `/etc/ember/`
// on Linux), resolved via `crate::paths::DaemonPaths::system()`. The
// daemon never needs HOME any more — it never reads from `$HOME` — so
// the renderers below DROP the HOME bake entirely. See the ADR 131
// 2026-06-14 amendment paragraph + ADR 218 §"Daemon-owned (AUTHORITY
// space) — OS system paths".

/// Path on disk for the macOS LaunchDaemon plist.
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";
/// Path on disk for the `emberd-rpc` sibling LaunchDaemon plist (ADR 155
/// SLICE 2b). Always staged; conditionally bootstrapped (see
/// [`rpc_sibling_should_bootstrap`]).
#[cfg(target_os = "macos")]
const LAUNCHD_RPC_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.rpc.plist";
#[cfg(target_os = "macos")]
const LAUNCHD_SANDBOX_DIR: &str = "/usr/local/lib/ember/sandbox";
#[cfg(target_os = "macos")]
const LAUNCHD_SANDBOX_PROFILE_PATH: &str = "/usr/local/lib/ember/sandbox/emberd.sb";
#[cfg(target_os = "macos")]
const EMBERD_SANDBOX_PROFILE_TEMPLATE: &str = include_str!("../templates/sandbox/emberd.sb");
#[cfg(target_os = "macos")]
const EMBERD_SANDBOX_WRITE_ALLOWLIST_TOKEN: &str = "__EMBERD_WRITE_ALLOWLIST__";

/// Render the macOS sandbox-exec profile body.
///
/// Per ADR 218 (operator-locked 2026-06-14): the daemon writes to system
/// paths under [`crate::paths::DaemonPaths::system().state_root`], NOT
/// to any user's `$HOME`. The pre-ADR-218 allowlist anchored on
/// `<operator_home>/.ember` is superseded; allowlist now anchors on the
/// system state-root (`/Library/Application Support/Emberlink/`).
///
/// `operator_home` is retained in the signature for call-site stability
/// across the multi-PR ADR-218 sequence; the parameter is unused.
#[cfg(target_os = "macos")]
fn render_launchd_sandbox_profile_body(_operator_home: &Path) -> String {
    let state_root = crate::paths::DaemonPaths::system().state_root;
    let state_root_regex = regex::escape(&state_root.to_string_lossy());
    let allowlist = format!(
        "(allow file-write*\n  \
         (regex #\"^{state_root_regex}(/|$)\")\n  \
         (regex #\"^/var/log/emberd(/|$)\")\n  \
         (regex #\"^/tmp/emberd-\")\n  \
         (regex #\"^/private/tmp/emberd-\")\n  \
         (regex #\"^/private/var/log/emberd(/|$)\"))"
    );
    EMBERD_SANDBOX_PROFILE_TEMPLATE.replace(EMBERD_SANDBOX_WRITE_ALLOWLIST_TOKEN, &allowlist)
}

/// Path on disk for the Linux systemd unit.
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/emberd.service";
/// Path on disk for the `emberd-rpc` sibling systemd unit (ADR 155 SLICE 2b).
/// Always staged; conditionally enabled (see [`rpc_sibling_should_bootstrap`]).
#[cfg(target_os = "linux")]
const SYSTEMD_RPC_UNIT_PATH: &str = "/etc/systemd/system/emberd-rpc.service";

/// Returns the rendered launchd plist body. Tests assert against this
/// helper so the writer and the assertion read from the same source.
///
/// Per ADR 218 (2026-06-14) this plist no longer bakes
/// `HOME=<operator_home>` into `EnvironmentVariables` — the daemon resolves
/// its at-rest state, runtime socket, pid file, and config exclusively via
/// [`crate::paths::DaemonPaths::system()`] (system paths under
/// `/Library/Application Support/Emberlink/`). `operator_home` is retained
/// in the signature for call-site stability across the multi-PR sequence;
/// the parameter is unused.
///
/// `dead_code` allowed because on a Linux non-test build there is no
/// caller (the macOS impl is excluded and tests don't compile).
#[allow(dead_code)]
pub(crate) fn render_launchd_plist_body(operator_home: &Path) -> String {
    render_launchd_plist_body_with_trust_roots(operator_home, "")
}

/// Render the prod LaunchDaemon plist with an optional `EMBER_TRUST_ROOTS`
/// environment entry. When `trust_roots` is non-empty it is emitted into the
/// EnvironmentVariables dict as the canonical comma-separated 64-hex pubkey
/// list that `crate::binary_manifest::parse_trust_roots` expects.
///
/// Empty `trust_roots` produces no entry so daemons that don't need to verify
/// a manifest keep a minimal env block; the daemon's startup gate
/// `runtime.rs::PATH-PINNING-STARTUP-VERIFY` already skips verification when
/// no manifest is on disk.
///
/// Per ADR 218 (2026-06-14) the rendered plist DROPS the historical
/// `<key>HOME</key>` entry: the daemon resolves its paths via
/// [`crate::paths::DaemonPaths::system()`] and no longer reads from `$HOME`.
/// `operator_home` is retained in the signature for call-site stability and
/// is unused. `EMBER_APP_PEM_PATH` / `EMBER_APP_ENV_PATH` remain — they point
/// at `/etc/emberlink/`, a system path that ADR 218 does not move.
pub(crate) fn render_launchd_plist_body_with_trust_roots(
    _operator_home: &Path,
    trust_roots: &str,
) -> String {
    // Optional EMBER_TRUST_ROOTS env entry — adds a line inside the
    // EnvironmentVariables <dict>. Empty trust_roots produces no line at
    // all, keeping the plist minimal on hosts that don't pin a binary
    // manifest.
    let trust_roots_env_line = if trust_roots.is_empty() {
        String::new()
    } else {
        format!("    <key>EMBER_TRUST_ROOTS</key><string>{trust_roots}</string>\n")
    };
    // emberd_launchd_sandbox_wired.
    //
    // ProgramArguments wrap `emberd` invocation in `sandbox-exec -f
    // <profile>` so the daemon process runs under the macOS TrustedBSD
    // MAC layer with the policy DSL from slice C
    // (`infra/sandbox/emberd.sb`, PR #3888 merged). macOS has no
    // direct seccomp equivalent; sandbox-exec is the closest primitive.
    //
    // The startup probe (slice E, PR #3900) invokes sandbox_check()
    // via libsandbox.dylib FFI at boot to verify the wrapper took
    // effect. On mismatch the daemon emits a loud WARN (or refuses
    // to start when EMBER_REQUIRE_SANDBOX=1 is in the EnvironmentVariables
    // block).
    //
    // Profile path: /usr/local/lib/ember/sandbox/emberd.sb (installed
    // by the daemon install path as a sibling of the binary; matches
    // ADR 131 install convention).
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n  \
           <key>Label</key>           <string>sh.emberlink.daemon</string>\n  \
           <key>UserName</key>        <string>ember</string>\n  \
           <key>GroupName</key>       <string>ember-clients</string>\n  \
           <key>EnvironmentVariables</key>\n  \
           <dict>\n    \
             <key>EMBER_APP_PEM_PATH</key><string>/etc/emberlink/ember-engine-app.pem</string>\n    \
             <key>EMBER_APP_ENV_PATH</key><string>/etc/emberlink/ember-engine.env</string>\n\
{trust_roots_env_line}  \
           </dict>\n  \
           <!-- emberd_launchd_sandbox_wired — sandbox-exec wrap per META-DAEMON-SECCOMP-PROFILE-HOST. -->\n  \
           <key>ProgramArguments</key>\n  \
           <array>\n    \
             <string>/usr/bin/sandbox-exec</string>\n    \
             <string>-f</string>\n    \
             <string>/usr/local/lib/ember/sandbox/emberd.sb</string>\n    \
             <string>/usr/local/bin/emberd</string>\n    \
             <string>--foreground</string>\n  \
           </array>\n  \
           <key>KeepAlive</key>       <true/>\n  \
           <key>RunAtLoad</key>       <true/>\n  \
           <key>StandardErrorPath</key><string>/var/log/emberd.err</string>\n  \
           <key>StandardOutPath</key> <string>/var/log/emberd.out</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Returns the rendered systemd unit body. Tests assert against this
/// helper so the writer and the assertion read from the same source.
///
/// Per ADR 218 (2026-06-14) this unit no longer bakes
/// `Environment=HOME=<operator_home>`: the daemon resolves its at-rest
/// state, runtime socket, pid file, and config exclusively via
/// [`crate::paths::DaemonPaths::system()`] (system paths: `/var/lib/ember/`,
/// `/run/ember/`, `/etc/ember/`). The unit declares those paths to systemd
/// via `StateDirectory=ember`, `RuntimeDirectory=ember`, and
/// `ConfigurationDirectory=ember` so the kernel manages creation,
/// teardown, and ownership (`ember:ember-clients`) for the daemon. The
/// group switches from `ember` to `ember-clients` so the group ACL on the
/// runtime dir / socket matches ADR 131 §"Auth model" + ADR 218 §"Socket
/// placement rationale". `operator_home` is retained in the signature for
/// call-site stability and is unused.
///
/// `dead_code` allowed because on a macOS non-test build there is no
/// caller (the Linux impl is excluded and tests don't compile).
#[allow(dead_code)]
pub(crate) fn render_systemd_unit_body(_operator_home: &Path) -> String {
    // emberd_systemd_seccomp_wired.
    //
    // `SystemCallFilter=` directives below apply systemd's seccomp wrapper
    // around the daemon process. The allowlist mirrors the JSON profile
    // shipped in `infra/seccomp/emberd-seccomp.json` (PR #3885, slice A),
    // expressed via systemd's pre-defined sets to avoid re-enumerating
    // ~193 syscalls inline. `@system-service` is systemd's curated
    // baseline for long-running services (covers file I/O, network,
    // signal, memory, time, IPC, basic process); we layer additional
    // explicit allows for fork/execve (broker-supervisor exec path,
    // ADR 124) + mlock (zeroize-on-drop credential handling).
    //
    // `~` prefix denies the named call. We deny @raw-io, @reboot,
    // @swap, @cpu-emulation, @debug, @mount, @module, @obsolete,
    // @privileged, @resources — the privileged surfaces emberd has no
    // business using.
    //
    // The startup probe (slice E, PR #3900) reads /proc/self/status
    // Seccomp: field at boot to verify this directive took effect. On
    // mismatch the daemon emits a loud WARN (or refuses to start when
    // EMBER_REQUIRE_SANDBOX=1 is in the Environment= block).
    //
    // ADR 218 directories: StateDirectory=ember resolves to
    // /var/lib/ember/, RuntimeDirectory=ember resolves to /run/ember/
    // (cleared on stop, recreated by systemd on start with the unit's
    // User/Group), ConfigurationDirectory=ember resolves to /etc/ember/.
    // Mode 0750 + Group=ember-clients gives the operator's session
    // (added to `ember-clients` at install time per ADR 131) traverse +
    // socket-connect rights without granting daemon-data read.
    //
    // ProtectHome=yes (stronger than the previous ProtectHome=read-only):
    // the daemon has no business in any user's $HOME under ADR 218 — it
    // never reads from there.
    "[Unit]\n\
     Description=Emberlink Grant Warden daemon\n\
     After=network.target\n\
     \n\
     [Service]\n\
     Type=simple\n\
     User=ember\n\
     Group=ember-clients\n\
     Environment=EMBER_APP_PEM_PATH=/etc/emberlink/ember-engine-app.pem\n\
     Environment=EMBER_APP_ENV_PATH=/etc/emberlink/ember-engine.env\n\
     ExecStart=/usr/local/bin/emberd --foreground\n\
     Restart=on-failure\n\
     RestartSec=5\n\
     \n\
     # ADR 218 system-paths — systemd manages /run/ember, /var/lib/ember,\n\
     # /etc/ember with the unit's User/Group at the modes below.\n\
     RuntimeDirectory=ember\n\
     RuntimeDirectoryMode=0750\n\
     StateDirectory=ember\n\
     StateDirectoryMode=0750\n\
     ConfigurationDirectory=ember\n\
     \n\
     # emberd_systemd_seccomp_wired — kernel sandbox per META-DAEMON-SECCOMP-PROFILE-HOST.\n\
     # Allowlist: systemd-curated baseline + explicit fork/exec/mlock.\n\
     SystemCallFilter=@system-service @ipc @memlock\n\
     SystemCallFilter=~@raw-io ~@reboot ~@swap ~@cpu-emulation ~@debug ~@mount ~@module ~@obsolete ~@privileged ~@resources\n\
     SystemCallErrorNumber=EPERM\n\
     SystemCallArchitectures=native\n\
     \n\
     # Defense-in-depth hardening — systemd primitives complement seccomp.\n\
     NoNewPrivileges=true\n\
     ProtectSystem=strict\n\
     ProtectHome=yes\n\
     PrivateTmp=true\n\
     PrivateDevices=true\n\
     ProtectKernelTunables=true\n\
     ProtectKernelModules=true\n\
     ProtectKernelLogs=true\n\
     ProtectControlGroups=true\n\
     RestrictNamespaces=true\n\
     RestrictRealtime=true\n\
     RestrictSUIDSGID=true\n\
     LockPersonality=true\n\
     MemoryDenyWriteExecute=true\n\
     \n\
     [Install]\n\
     WantedBy=multi-user.target\n"
        .to_string()
}

// ── ADR 155 SLICE 2b — emberd-rpc sibling unit bodies ──────────────────────
//
// Path-pin derivation (see the SLICE 2b block comment near
// `install_emberd_rpc_binary` for the full rationale). The prod daemon resolves
// its path-bearing state via `DaemonPaths::system()` per ADR 218. emberd core
// writes the sibling's TLS material to:
//   <data_dir>/ember-rpc/server.crt     (runtime.rs:4007)
//   <data_dir>/ember-rpc/server.key     (runtime.rs:4008)
//   <data_dir>/bridge_ca.pem            (runtime.rs:3877/3902)
// and the rpc forward UDS the sibling connects to is:
//   <run_dir>/rpc.sock                  (runtime.rs:50, socket_dir/rpc.sock)
// The sibling reads these from EMBER_RPC_{FORWARD_UDS,SERVER_CERT,SERVER_KEY,
// CA_CERT} (ember-rpc/src/main.rs:43-59). We pin all four here because the
// sibling's own Config::default() points at the FHS /var/{run,lib}/emberd
// layout the prod daemon does NOT use on macOS, and because launchd/systemd
// services must not infer authority-space state from an operator HOME.

/// Render each `EMBER_RPC_*` pin from the daemon's system path layout.
///
/// `operator_home` is retained in the signature for call-site stability, but
/// ADR 218 moved daemon-owned state and runtime sockets out of user homes.
/// The RPC sibling is part of authority space and must read the same system
/// path material the daemon writes.
///
/// Returns `(forward_uds, server_cert, server_key, ca_cert)`.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux", test)),
    allow(dead_code)
)]
fn rpc_env_pins(_operator_home: &Path) -> (String, String, String, String) {
    let paths = crate::paths::DaemonPaths::system();
    let forward_uds = paths.run_dir.join("rpc.sock");
    let data = paths.data_dir;
    let server_cert = data.join("ember-rpc").join("server.crt");
    let server_key = data.join("ember-rpc").join("server.key");
    let ca_cert = data.join("bridge_ca.pem");
    (
        forward_uds.to_string_lossy().into_owned(),
        server_cert.to_string_lossy().into_owned(),
        server_key.to_string_lossy().into_owned(),
        ca_cert.to_string_lossy().into_owned(),
    )
}

/// Render the `sh.emberlink.rpc` LaunchDaemon plist body with the four
/// system-path `EMBER_RPC_*` pins baked into `EnvironmentVariables`.
/// Modeled on [`render_launchd_plist_body_with_trust_roots`]. Tests assert
/// against this helper so the writer and the assertion share one source.
///
/// `dead_code`/`unused` allowed on non-macOS non-test builds where there is no
/// caller (the writer is macOS-only).
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn render_rpc_launchd_plist_body(operator_home: &Path) -> String {
    let (forward_uds, server_cert, server_key, ca_cert) = rpc_env_pins(operator_home);
    // ember_rpc_sibling_bootstrap_landed (rendered authoritative unit).
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n  \
           <key>Label</key>           <string>sh.emberlink.rpc</string>\n  \
           <key>UserName</key>        <string>ember</string>\n  \
           <key>EnvironmentVariables</key>\n  \
           <dict>\n    \
             <key>EMBER_RPC_FORWARD_UDS</key><string>{forward_uds}</string>\n    \
             <key>EMBER_RPC_SERVER_CERT</key><string>{server_cert}</string>\n    \
             <key>EMBER_RPC_SERVER_KEY</key><string>{server_key}</string>\n    \
             <key>EMBER_RPC_CA_CERT</key><string>{ca_cert}</string>\n  \
           </dict>\n  \
           <key>ProgramArguments</key>\n  \
           <array>\n    \
             <string>/usr/local/bin/emberd-rpc-macos</string>\n  \
           </array>\n  \
           <key>RunAtLoad</key>       <true/>\n  \
           <key>KeepAlive</key>       <true/>\n  \
           <key>ThrottleInterval</key><integer>10</integer>\n  \
           <key>StandardErrorPath</key><string>/var/log/emberd-rpc.err</string>\n  \
           <key>StandardOutPath</key> <string>/var/log/emberd-rpc.out</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Render the `emberd-rpc.service` systemd unit body with the four
/// system-path `EMBER_RPC_*` pins as `Environment=` lines, carrying
/// forward ALL the hardening from the `infra/systemd/emberd-rpc.service`
/// reference scaffold. Modeled on [`render_systemd_unit_body`].
///
/// ## ProtectHome / ProtectSystem vs cert readability (load-bearing)
///
/// `ProtectSystem=strict` makes the whole filesystem read-only **except** the
/// paths systemd is told to expose. The sibling MUST be able to (a) READ its
/// TLS material under the daemon data dir and (b) CONNECT to the forward UDS
/// under the daemon run dir. If those paths are hidden the sibling fails
/// closed (cert-not-found → restart loop) — a silent lane failure.
///
/// Resolution (the systemd.exec(5)-documented combination): `ProtectHome=tmpfs`
/// overlays the operator home with an empty tmpfs, then `BindReadOnlyPaths=` /
/// `BindPaths=` bind-mount the two real `.ember` subtrees back into the
/// namespace (the systemd bind family is `BindPaths=` [read-write] /
/// `BindReadOnlyPaths=` [read-only] — there is no `BindReadWritePaths=`). We do
/// NOT use `ProtectHome=true` + `ReadOnlyPaths=`: an adversarial review
/// (2026-06-05) raised — from the systemd.exec(5) wording on `InaccessiblePaths=`
/// nesting — that `ReadOnlyPaths=` might not re-expose through the overlay
/// `ProtectHome=true` installs over `/home`. Empirical validation on systemd 257
/// found BOTH combos DO re-expose the cert (so it was not the universal failure
/// the review claimed), but `BindReadOnlyPaths=`/`BindPaths=` under
/// `ProtectHome=tmpfs` is the man page's explicit "hide home but expose
/// necessary dirs" pattern — kept for clarity and cross-version robustness
/// (older systemd may differ from 257). Validated on systemd 257: cert readable
/// + forward-UDS connectable through this namespace.
///
/// `data/` is bound read-only (the sibling only READS
/// its cert/key/ca — integrity-protected against a compromised mTLS parser);
/// `run/` is bound read-write so `connect(2)` to the forward UDS is unimpeded
/// (same `ember` uid that already owns the dir — no new privilege). The `-`
/// prefix tolerates a path not yet existing at namespace setup (async cert
/// mint), so a racing sibling soft-fails on the missing cert and self-heals.
///
/// NOTE: the string-match test for this fn cannot prove the namespace actually
/// re-exposes the cert at runtime — that requires booting the unit on real
/// systemd (a Linux-VM validation step), NOT the macOS worktree.
///
/// `dead_code` allowed on non-Linux non-test builds (writer is Linux-only).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) fn render_rpc_systemd_unit_body(operator_home: &Path) -> String {
    let (forward_uds, server_cert, server_key, ca_cert) = rpc_env_pins(operator_home);
    let paths = crate::paths::DaemonPaths::system();
    let data_dir = paths.data_dir;
    let run_dir = paths.run_dir;
    let data_dir = data_dir.display();
    let run_dir = run_dir.display();
    // ember_rpc_sibling_bootstrap_landed (rendered authoritative unit).
    format!(
        "[Unit]\n\
         Description=Ember RPC frontend (mTLS lane) — ADR 155 amendment\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=ember\n\
         Group=ember\n\
         ExecStart=/usr/local/bin/emberd-rpc-linux\n\
         # 2c cert hot-reload entry point — SIGHUP re-reads the rotated server cert.\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         Restart=always\n\
         RestartSec=5\n\
         StartLimitBurst=10\n\
         StartLimitIntervalSec=120\n\
         Environment=EMBER_RPC_FORWARD_UDS={forward_uds}\n\
         Environment=EMBER_RPC_SERVER_CERT={server_cert}\n\
         Environment=EMBER_RPC_SERVER_KEY={server_key}\n\
         Environment=EMBER_RPC_CA_CERT={ca_cert}\n\
         \n\
         # Cap-drop=ALL — ember-rpc binds an unprivileged loopback port, reads\n\
         # TLS bytes, forwards bincode over a UDS it owns by uid. No privileged op.\n\
         CapabilityBoundingSet=\n\
         AmbientCapabilities=\n\
         NoNewPrivileges=true\n\
         \n\
         # Filesystem hardening (see the fn doc-comment for the ProtectHome/Bind\n\
         # interaction rationale).\n\
         ProtectSystem=strict\n\
         # ProtectHome=tmpfs (NOT =true) overlays the operator home with an empty\n\
         # tmpfs; the Bind*Paths= below bind-mount the two real .ember subtrees\n\
         # back into the namespace — the systemd.exec(5)-documented 'hide home but\n\
         # expose necessary dirs' pattern (validated on systemd 257: cert readable\n\
         # + forward-UDS connectable). See the fn doc-comment for why this is\n\
         # preferred over ProtectHome=true + ReadOnlyPaths=.\n\
         ProtectHome=tmpfs\n\
         # `-` prefix tolerates the dir not existing yet at namespace setup (the\n\
         # cert is minted async on a fresh bridge-on host; a sibling that races\n\
         # ahead soft-fails on the missing cert and self-heals on the next\n\
         # restart). data/ is BindReadOnlyPaths (read-only — the sibling only\n\
         # READS its cert/key/ca, integrity-protected); run/ is BindPaths\n\
         # (read-write — the systemd bind family is BindPaths=/BindReadOnlyPaths=,\n\
         # there is NO BindReadWritePaths=) so connect(2) to the forward UDS is\n\
         # unimpeded (same ember uid that already owns the dir).\n\
         BindReadOnlyPaths=-{data_dir}\n\
         BindPaths=-{run_dir}\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictNamespaces=true\n\
         RestrictRealtime=true\n\
         LockPersonality=true\n\
         MemoryDenyWriteExecute=true\n\
         \n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=10\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Resolve the operator's home directory under a sudo-elevated install.
///
/// Under `sudo`, the calling process's `getuid()` is `0` (root), so
/// `dirs_next::home_dir()` returns `/var/root` — not the home of the
/// human operator who actually ran the install. `sudo` does, however,
/// preserve `$SUDO_USER`, which gives the invoking user's name. This
/// helper resolves the operator via `resolve_operator_user`
/// (`$EMBER_OPERATOR` > `$SUDO_USER` > `$USER`) and looks up that user's
/// home via `getpwnam_r`. `$EMBER_OPERATOR` is the macOS `.pkg` lane's
/// channel: its postinstall runs as a pure-root login with no `$SUDO_USER`,
/// so it pins the console user explicitly.
///
/// Returns `InstallError::Subprocess` with a clear hint when the install
/// is being run as root with no operator signal to anchor to — that's the
/// "logged in as root directly" case the install isn't designed for.
pub fn resolve_operator_home() -> Result<PathBuf, InstallError> {
    let user = resolve_operator_user()?;
    home_for_user(&user).ok_or_else(|| InstallError::Subprocess {
        cmd: "resolve_operator_home".to_string(),
        stderr: format!("getpwnam_r for {user:?} returned no home directory"),
        exit_code: None,
    })
}

fn resolve_operator_user() -> Result<String, InstallError> {
    // `EMBER_OPERATOR` takes precedence over `$SUDO_USER`/`$USER`. The macOS
    // `.pkg` postinstall runs as a pure-root login (spawned by
    // `package_script_service`, which does not inherit `$SUDO_USER` even when
    // the operator launched `sudo installer`), so there is no environment
    // signal for the human operator. The postinstall resolves the console user
    // (`stat -f%Su /dev/console`) and pins it here. Outside the pkg lane the
    // var is unset, so `sudo ember daemon install` keeps its prior behavior.
    let user = std::env::var("EMBER_OPERATOR")
        .or_else(|_| std::env::var("SUDO_USER"))
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();

    if user.is_empty() || user == "root" {
        return Err(InstallError::Subprocess {
            cmd: "resolve_operator_home".to_string(),
            stderr: format!(
                "could not resolve invoking-operator home: EMBER_OPERATOR={:?} \
                 SUDO_USER={:?} USER={:?}. Run via `sudo ember daemon install` \
                 from a regular user shell, or set EMBER_OPERATOR to the target \
                 operator (the macOS .pkg postinstall does this from the console user).",
                std::env::var("EMBER_OPERATOR").ok(),
                std::env::var("SUDO_USER").ok(),
                std::env::var("USER").ok()
            ),
            exit_code: None,
        });
    }

    Ok(user)
}

/// Look up a username's home directory via `getpwnam_r(3)`. Returns
/// `None` if the user does not exist or the entry has no home dir.
fn home_for_user(user: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};

    let cuser = CString::new(user).ok()?;
    // `libc::c_char` is `i8` on macOS / `u8` on Linux; using the platform alias
    // keeps `home_for_user` portable across both targets (caught Linux build red
    // 2026-05-12 after #2720 landed with `vec![0i8; ...]` which breaks the
    // `libc::getpwnam_r` arg-3 type expected `*mut u8` on Linux).
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: zeroed `passwd` is a valid initial state for getpwnam_r;
    // the call fills it or returns non-zero/null.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `cuser` outlives the call; `buf` and `pwd` are exclusively
    // borrowed for the duration; `result` is an out-parameter pointer
    // that the C call fills with either &pwd or NULL.
    let rc = unsafe {
        libc::getpwnam_r(
            cuser.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pwd.pw_dir is a NUL-terminated C string owned by `buf` for
    // the lifetime of this function.
    let cstr = unsafe { CStr::from_ptr(pwd.pw_dir) };
    Some(PathBuf::from(cstr.to_string_lossy().into_owned()))
}

/// Install the `sh.emberlink.daemon` LaunchDaemon plist at
/// `/Library/LaunchDaemons/sh.emberlink.daemon.plist` and bootstrap it
/// into the system domain (per ADR 131 §macOS install).
///
/// **Idempotent.** If the plist on disk already matches the rendered
/// body, the function skips the bootout/bootstrap cycle. Otherwise the
/// plist is rewritten, mode is reset to `0644`, the existing service is
/// `launchctl bootout`-ed (tolerating "not currently bootstrapped"), and
/// then `launchctl bootstrap`-ed.
///
/// Requires root (typically invoked under `sudo` from the installer
/// entry point) — the LaunchDaemons directory and `launchctl ...
/// system` both reject non-root callers.
#[cfg(target_os = "macos")]
pub fn install_launchd_plist(operator_home: &Path) -> Result<(), InstallError> {
    install_launchd_plist_with_trust_roots(operator_home, "")
}

/// Install the LaunchDaemon plist with an `EMBER_TRUST_ROOTS` environment
/// entry baked into the EnvironmentVariables dict. The value must be a
/// comma-separated list of 64-char lower-hex Ed25519 public keys (the shape
/// [`crate::binary_manifest::parse_trust_roots`] consumes). An empty string
/// falls through to the legacy plist with no trust-roots entry — the daemon
/// then refuses to load any binary manifest, which is the historical posture
/// for hosts that don't pin Construct binaries.
#[cfg(target_os = "macos")]
pub fn install_launchd_plist_with_trust_roots(
    operator_home: &Path,
    trust_roots: &str,
) -> Result<(), InstallError> {
    // Publish the emberd binary first — the plist's ProgramArguments
    // references /usr/local/bin/emberd; bootstrap silently exec-fails
    // with ENOENT if the binary is missing.
    install_emberd_binary()?;
    install_launchd_sandbox_profile(operator_home)?;
    park_incompatible_launchd_binary_manifest(operator_home, trust_roots)?;

    let path = Path::new(LAUNCHD_PLIST_PATH);
    let body = render_launchd_plist_body_with_trust_roots(operator_home, trust_roots);

    // Idempotency check — skip the bootout/bootstrap cycle only when
    // BOTH (a) the on-disk plist content already matches AND (b) the
    // service is currently loaded by launchd. The content-only check
    // (the previous shape) is insufficient: a re-install after an
    // operator manually parked the plist (`mv plist /tmp; mv back`) or
    // after a failed bootout would see matching content but no loaded
    // service, and would silently skip the bootstrap, leaving the
    // daemon unregistered. Caught during the Plan-J test cycle —
    // operator parked the plist for a race-free cleanup, install
    // hit content-equality, skipped bootstrap, daemon never came up.
    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    let log_paths_repaired = ensure_emberd_log_paths()?;
    let stale_runtime_cleared = clear_stale_launchd_runtime_artifacts(operator_home)?;

    if !already_matches
        || !is_launchd_service_active()
        || log_paths_repaired
        || stale_runtime_cleared
    {
        write_root_install_file_atomic(path, body.as_bytes())?;

        run("chmod", &["0644", LAUNCHD_PLIST_PATH], false)?;

        // bootout — tolerate "not currently bootstrapped" (exit 113 or
        // stderr containing "Could not find specified service"). This
        // is the macOS-launchctl analogue of `groupadd --force`.
        bootout_tolerant()?;

        run(
            "launchctl",
            &["bootstrap", "system", LAUNCHD_PLIST_PATH],
            false,
        )?;

        wait_for_launchd_runtime_artifacts(operator_home)?;
    }

    // ADR 155 SLICE 2b — stage (+ conditionally bootstrap) the emberd-rpc
    // sibling alongside the core daemon. Errors propagate so a failed sibling
    // stage fails the install loudly rather than leaving a half-wired host.
    install_rpc_plist(operator_home)?;

    Ok(())
}

/// Stage (and conditionally bootstrap) the `emberd-rpc` sibling LaunchDaemon
/// (ADR 155 SLICE 2b, "Option A" lifecycle).
///
/// `ember_rpc_sibling_bootstrap_landed` — install-lane entry point for the
/// `emberd-rpc` mTLS-frontend sibling.
///
/// Steps:
/// 1. Publish the platform binary to `/usr/local/bin/emberd-rpc-macos`.
/// 2. Render the plist with daemon system-path `EMBER_RPC_*` pins and
///    write it to `/Library/LaunchDaemons/sh.emberlink.rpc.plist` (mode 0644)
///    — ALWAYS, so the unit is ready the moment the bridge is enabled.
/// 3. If the bridge is configured ON ([`rpc_sibling_should_bootstrap`]):
///    `launchctl bootstrap` it (bootout-tolerant first), then verify it loaded.
///    Else: ensure it is NOT loaded (bootout-tolerant) so toggling the bridge
///    off actually stops a previously-bootstrapped sibling (hard-right symmetry).
///
/// ## Idempotency (Plan-J lesson)
///
/// The content-only skip is a known bug: a re-install after the plist was
/// parked or a failed bootstrap sees matching content but no loaded service and
/// silently skips bootstrap. We mirror `install_launchd_plist_with_trust_roots`:
/// skip the write/bootstrap cycle ONLY when the on-disk content matches AND the
/// desired loaded-state already holds.
///
/// Requires root (LaunchDaemons dir + `launchctl ... system` reject non-root).
#[cfg(target_os = "macos")]
pub fn install_rpc_plist(operator_home: &Path) -> Result<(), InstallError> {
    // Publish the sibling binary first — the plist's ProgramArguments
    // references /usr/local/bin/emberd-rpc-macos; bootstrap silently
    // exec-fails with ENOENT if the binary is missing.
    install_emberd_rpc_binary()?;

    let path = Path::new(LAUNCHD_RPC_PLIST_PATH);
    let body = render_rpc_launchd_plist_body(operator_home);
    let should_bootstrap = rpc_sibling_should_bootstrap(operator_home);

    // Pre-create the rpc log paths the same way emberd's are pre-created:
    // launchd opens StandardError/OutPath as root then hands the fds to the
    // ember-uid process, but /var/log is root:wheel so the ember user can't
    // create them. Only needed when we actually bootstrap.
    let log_paths_repaired = if should_bootstrap {
        ensure_emberd_rpc_log_paths()?
    } else {
        false
    };

    let content_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);
    let loaded = is_launchd_rpc_service_loaded();
    // Desired loaded-state already holds?
    let state_converged = loaded == should_bootstrap;

    if content_matches && state_converged && !log_paths_repaired {
        return Ok(());
    }

    write_root_install_file_atomic(path, body.as_bytes())?;
    run("chmod", &["0644", LAUNCHD_RPC_PLIST_PATH], false)?;

    if should_bootstrap {
        // Clear any sticky `launchctl disable` override left by a prior
        // bridge-OFF install — a disabled service refuses to `bootstrap`, and
        // enable/disable overrides persist in launchd's db across reboots.
        run("launchctl", &["enable", "system/sh.emberlink.rpc"], false)?;
        // bootout-tolerant first so a stale/old-content unit is replaced.
        bootout_rpc_tolerant()?;
        run(
            "launchctl",
            &["bootstrap", "system", LAUNCHD_RPC_PLIST_PATH],
            false,
        )?;
        // Verify it actually REGISTERED — don't silent-no-op. NOTE: this
        // confirms bootstrap-domain membership, NOT a running process — a
        // sibling that registers then crash-loops on a missing/rotating cert
        // still reports loaded (the async cert mint can race this verify on a
        // fresh bridge-ON install; Restart/KeepAlive self-heals). A bridge-ON
        // host that fails to register AT ALL is a real install failure.
        if !is_launchd_rpc_service_loaded() {
            return Err(InstallError::Subprocess {
                cmd: format!("launchctl bootstrap system {LAUNCHD_RPC_PLIST_PATH}"),
                stderr: "emberd-rpc sibling did not load after bootstrap \
                         (bridge is configured ON; check /var/log/emberd-rpc.err)"
                    .to_string(),
                exit_code: None,
            });
        }
    } else {
        // Bridge OFF: stop the current session AND write a persistent disabled
        // override. The rendered plist has RunAtLoad/KeepAlive=true, so a plist
        // merely RESIDENT in /Library/LaunchDaemons auto-loads at the NEXT BOOT
        // — `bootout` only unloads the current session. Without the `disable`
        // override a staged-OFF sibling would auto-start after a reboot, find no
        // cert (minted only in the daemon's bridge-ON branch), and crash-loop,
        // defeating "inert until enabled". (Added after adversarial review,
        // 2026-06-05.)
        bootout_rpc_tolerant()?;
        run("launchctl", &["disable", "system/sh.emberlink.rpc"], false)?;
    }

    Ok(())
}

/// Non-macOS fallback for [`install_rpc_plist`].
#[cfg(not(target_os = "macos"))]
pub fn install_rpc_plist(_operator_home: &Path) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_rpc_plist".to_string(),
        stderr: "unsupported platform: emberd-rpc plist install is macOS-only".to_string(),
        exit_code: None,
    })
}

/// True if the `sh.emberlink.rpc` LaunchDaemon is currently loaded by launchd.
/// We use the looser "service exists in the print output" check (exit 0) rather
/// than the strict active-process check used for emberd core: on a bridge-ON
/// host with no cert yet the sibling may be flapping, but it is still
/// *bootstrapped* (loaded), which is what we gate the install convergence on.
#[cfg(target_os = "macos")]
fn is_launchd_rpc_service_loaded() -> bool {
    Command::new("launchctl")
        .args(["print", "system/sh.emberlink.rpc"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// `launchctl bootout system <rpc-plist>` tolerating "not currently
/// bootstrapped" across macOS versions. Reuses [`bootout_tolerant_inner`] so
/// the version-specific tolerance table is shared with the emberd-core path.
#[cfg(target_os = "macos")]
fn bootout_rpc_tolerant() -> Result<(), InstallError> {
    let cmd_string = format!("launchctl bootout system {LAUNCHD_RPC_PLIST_PATH}");
    bootout_tolerant_inner(&cmd_string, || {
        let output = Command::new("launchctl")
            .args(["bootout", "system", LAUNCHD_RPC_PLIST_PATH])
            .output()
            .map_err(|e| InstallError::Subprocess {
                cmd: cmd_string.clone(),
                stderr: format!("spawn failed: {e}"),
                exit_code: None,
            })?;
        let exit_code = output.status.code();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok((exit_code, stderr, output.status.success()))
    })
}

/// Standard error/out log paths written into the rpc sibling's plist. Same
/// EX_CONFIG-on-missing-file requirement as the emberd-core log paths.
#[cfg(target_os = "macos")]
const EMBERD_RPC_LOG_ERR: &str = "/var/log/emberd-rpc.err";
#[cfg(target_os = "macos")]
const EMBERD_RPC_LOG_OUT: &str = "/var/log/emberd-rpc.out";

/// Pre-create `/var/log/emberd-rpc.{err,out}` owned by the `ember` user so
/// launchd can hand the fds to the ember-uid sibling. Delegates to the shared
/// [`ensure_emberd_log_paths_inner`] (same EX_CONFIG-on-missing-file failure
/// mode and chown-via-`libc::chown` mechanics as the emberd-core path).
/// Returns true if either file was created/repaired.
#[cfg(target_os = "macos")]
fn ensure_emberd_rpc_log_paths() -> Result<bool, InstallError> {
    ensure_emberd_log_paths_inner(
        Path::new(EMBERD_RPC_LOG_ERR),
        Path::new(EMBERD_RPC_LOG_OUT),
        ember_user_uid_gid,
        |path, uid, gid| {
            use std::ffi::CString;
            let path_c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| {
                InstallError::Subprocess {
                    cmd: format!("chown {}", path.display()),
                    stderr: format!("path contains NUL: {e}"),
                    exit_code: None,
                }
            })?;
            // SAFETY: path_c is a valid NUL-terminated C string; uid/gid come
            // from getpwnam_r for the provisioned `ember` user.
            let rc = unsafe { libc::chown(path_c.as_ptr(), uid, gid) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(InstallError::Subprocess {
                    cmd: format!("chown {}:{} {}", uid, gid, path.display()),
                    stderr: format!("chown failed: {err}"),
                    exit_code: Some(rc),
                });
            }
            Ok(())
        },
    )
}

#[cfg(target_os = "macos")]
fn clear_stale_launchd_runtime_artifacts(_operator_home: &Path) -> Result<bool, InstallError> {
    // ADR 218: runtime artifacts (socket + pid) live at the system run dir
    // (`/Library/Application Support/Emberlink/run/`). The `_operator_home`
    // argument is retained for call-site stability and is unused.
    clear_stale_launchd_runtime_artifacts_inner(&crate::paths::DaemonPaths::system())
}

#[cfg(target_os = "macos")]
fn clear_stale_launchd_runtime_artifacts_inner(
    paths: &crate::paths::DaemonPaths,
) -> Result<bool, InstallError> {
    let run_dir = &paths.run_dir;
    let mut changed = false;
    for path in [run_dir.join("emberd.pid"), run_dir.join("daemon.sock")] {
        match std::fs::remove_file(&path) {
            Ok(()) => changed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(InstallError::Subprocess {
                    cmd: format!("rm {}", path.display()),
                    stderr: format!("remove_file failed: {e}"),
                    exit_code: None,
                });
            }
        }
    }
    Ok(changed)
}

#[cfg(target_os = "macos")]
fn wait_for_launchd_runtime_artifacts(_operator_home: &Path) -> Result<(), InstallError> {
    const MAX_ATTEMPTS: usize = 50;
    const SLEEP_MS: u64 = 100;

    // ADR 218: runtime artifacts under the system run dir; `_operator_home`
    // retained for call-site stability and unused.
    let paths = crate::paths::DaemonPaths::system();
    let run_dir = paths.run_dir;
    let pid_path = run_dir.join("emberd.pid");
    let socket_path = run_dir.join("daemon.sock");

    wait_for_launchd_runtime_artifacts_inner(
        MAX_ATTEMPTS,
        || pid_path.exists() && socket_path.exists(),
        || std::thread::sleep(std::time::Duration::from_millis(SLEEP_MS)),
        || launchd_runtime_timeout_diagnostics(&pid_path, &socket_path),
    )
}

#[cfg(target_os = "macos")]
fn wait_for_launchd_runtime_artifacts_inner<P, S, D>(
    max_attempts: usize,
    probe: P,
    sleep: S,
    diagnostics: D,
) -> Result<(), InstallError>
where
    P: Fn() -> bool,
    S: Fn(),
    D: Fn() -> String,
{
    for attempt in 0..max_attempts {
        if probe() {
            return Ok(());
        }
        if attempt + 1 < max_attempts {
            sleep();
        }
    }

    Err(InstallError::Subprocess {
        cmd: "launchctl bootstrap system sh.emberlink.daemon".to_string(),
        stderr: format!(
            "daemon install completed but the managed runtime artifacts never reappeared\n{}",
            diagnostics()
        ),
        exit_code: None,
    })
}

#[cfg(target_os = "macos")]
fn launchd_runtime_timeout_diagnostics(pid_path: &Path, socket_path: &Path) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "runtime artifact state: pid_file={} present={}, socket={} present={}",
        pid_path.display(),
        pid_path.exists(),
        socket_path.display(),
        socket_path.exists()
    ));

    match Command::new("launchctl")
        .args(["print", "system/sh.emberlink.daemon"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            out.push_str("\nlaunchctl print system/sh.emberlink.daemon:\n");
            out.push_str(&last_lines(stdout.trim(), 80));
            if !stderr.trim().is_empty() {
                out.push_str("\nlaunchctl stderr:\n");
                out.push_str(&last_lines(stderr.trim(), 20));
            }
        }
        Err(e) => {
            out.push_str(&format!("\nlaunchctl print failed: {e}"));
        }
    }

    for log_path in ["/var/log/emberd.err", "/var/log/emberd.out"] {
        match std::fs::read_to_string(log_path) {
            Ok(text) if !text.trim().is_empty() => {
                out.push_str(&format!("\nlast lines from {log_path}:\n"));
                out.push_str(&last_lines(text.trim(), 40));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                out.push_str(&format!("\nread {log_path} failed: {e}"));
            }
        }
    }

    out
}

#[cfg(target_os = "macos")]
fn last_lines(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

#[cfg(target_os = "macos")]
fn park_incompatible_launchd_binary_manifest(
    operator_home: &Path,
    install_trust_roots: &str,
) -> Result<bool, InstallError> {
    let manifest_path = crate::binary_manifest::bundled_install_dir().join("manifest.toml");
    let trust_roots = launchd_binary_manifest_trust_roots(operator_home, install_trust_roots)?;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown-time".to_string());
    park_incompatible_launchd_binary_manifest_inner(&manifest_path, &trust_roots, &suffix)
}

#[cfg(target_os = "macos")]
fn launchd_binary_manifest_trust_roots(
    operator_home: &Path,
    install_trust_roots: &str,
) -> Result<Vec<ed25519_dalek::VerifyingKey>, InstallError> {
    let mut roots = Vec::new();
    if let Ok(release_pk) =
        ed25519_dalek::VerifyingKey::from_bytes(&crate::trust_graph::EMBER_SYSTEMS_PUBKEY_BYTES)
    {
        roots.push(release_pk);
    }

    let trust_root_text = read_launchd_config_trust_roots(operator_home)?;
    let user_roots = crate::binary_manifest::parse_trust_roots(&trust_root_text).map_err(|e| {
        InstallError::Subprocess {
            cmd: "parse launchd binary manifest trust roots".to_string(),
            stderr: format!(
                "could not parse [daemon].trust_roots from {}: {e}",
                crate::paths::DaemonPaths::system().config_file().display()
            ),
            exit_code: None,
        }
    })?;
    roots.extend(user_roots);

    let install_roots =
        crate::binary_manifest::parse_trust_roots(install_trust_roots).map_err(|e| {
            InstallError::Subprocess {
                cmd: "parse launchd binary manifest install trust roots".to_string(),
                stderr: format!("could not parse installer-supplied EMBER_TRUST_ROOTS: {e}"),
                exit_code: None,
            }
        })?;
    roots.extend(install_roots);
    Ok(roots)
}

#[cfg(target_os = "macos")]
fn read_launchd_config_trust_roots(_operator_home: &Path) -> Result<String, InstallError> {
    // ADR 218: daemon config at the system path; `_operator_home` retained
    // for call-site stability and unused.
    let config_path = crate::paths::DaemonPaths::system().config_file();
    let text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => {
            return Err(InstallError::Subprocess {
                cmd: format!("read {}", config_path.display()),
                stderr: format!("read failed: {e}"),
                exit_code: None,
            });
        }
    };

    let value: toml::Value = toml::from_str(&text).map_err(|e| InstallError::Subprocess {
        cmd: format!("parse {}", config_path.display()),
        stderr: format!("toml parse failed: {e}"),
        exit_code: None,
    })?;
    Ok(value
        .get("daemon")
        .and_then(|daemon| daemon.get("trust_roots"))
        .and_then(|roots| roots.as_str())
        .unwrap_or("")
        .to_string())
}

#[cfg(target_os = "macos")]
fn park_incompatible_launchd_binary_manifest_inner(
    manifest_path: &Path,
    trust_roots: &[ed25519_dalek::VerifyingKey],
    suffix: &str,
) -> Result<bool, InstallError> {
    if !manifest_path.exists() {
        return Ok(false);
    }

    match crate::binary_manifest::verify_manifest_signature_with_trust_roots(
        manifest_path,
        trust_roots,
    ) {
        Ok(()) => Ok(false),
        Err(e) => {
            let parked_manifest = rejected_manifest_path(manifest_path, suffix);
            std::fs::rename(manifest_path, &parked_manifest).map_err(|rename_err| {
                InstallError::Subprocess {
                    cmd: format!(
                        "mv {} {}",
                        manifest_path.display(),
                        parked_manifest.display()
                    ),
                    stderr: format!(
                        "manifest failed launchd trust-root verification ({e}); rename failed: {rename_err}"
                    ),
                    exit_code: None,
                }
            })?;

            let sidecar_path = manifest_path.with_extension("toml.sig");
            if sidecar_path.exists() {
                let parked_sidecar = rejected_manifest_path(&sidecar_path, suffix);
                std::fs::rename(&sidecar_path, &parked_sidecar).map_err(|rename_err| {
                    InstallError::Subprocess {
                        cmd: format!(
                            "mv {} {}",
                            sidecar_path.display(),
                            parked_sidecar.display()
                        ),
                        stderr: format!(
                            "manifest failed launchd trust-root verification ({e}); sidecar rename failed: {rename_err}"
                        ),
                        exit_code: None,
                    }
                })?;
            }

            tracing::warn!(
                manifest = %manifest_path.display(),
                parked = %parked_manifest.display(),
                error = %e,
                "parked binary manifest that is incompatible with the launchd trust roots"
            );
            Ok(true)
        }
    }
}

#[cfg(target_os = "macos")]
fn rejected_manifest_path(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("manifest.toml");
    path.with_file_name(format!("{name}.rejected-{suffix}"))
}

#[cfg(target_os = "macos")]
fn install_launchd_sandbox_profile(operator_home: &Path) -> Result<(), InstallError> {
    let dir = Path::new(LAUNCHD_SANDBOX_DIR);
    std::fs::create_dir_all(dir).map_err(|e| InstallError::Subprocess {
        cmd: format!("mkdir -p {}", dir.display()),
        stderr: format!("create_dir_all failed: {e}"),
        exit_code: None,
    })?;

    install_launchd_sandbox_profile_into(Path::new(LAUNCHD_SANDBOX_PROFILE_PATH), operator_home)?;

    run("chmod", &["0755", LAUNCHD_SANDBOX_DIR], false)?;
    run("chmod", &["0644", LAUNCHD_SANDBOX_PROFILE_PATH], false)?;
    run("chown", &["root:wheel", LAUNCHD_SANDBOX_DIR], false)?;
    run(
        "chown",
        &["root:wheel", LAUNCHD_SANDBOX_PROFILE_PATH],
        false,
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd_sandbox_profile_into(
    dst: &Path,
    operator_home: &Path,
) -> Result<(), InstallError> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InstallError::Subprocess {
            cmd: format!("mkdir -p {}", parent.display()),
            stderr: format!("create_dir_all failed: {e}"),
            exit_code: None,
        })?;
    }

    let rendered = render_launchd_sandbox_profile_body(operator_home);
    let existing = std::fs::read_to_string(dst).ok();
    if existing.as_deref() != Some(rendered.as_str()) {
        write_root_install_file_atomic(dst, rendered.as_bytes())?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o644)).map_err(|e| {
            InstallError::Subprocess {
                cmd: format!("chmod 0644 {}", dst.display()),
                stderr: format!("set_permissions failed: {e}"),
                exit_code: None,
            }
        })?;
    }

    Ok(())
}

/// True when `launchctl print system/sh.emberlink.daemon` shows the
/// daemon is both registered and has an active process. A dead
/// crash-looping service still appears in `launchctl print`, but with
/// `active count = 0`; reinstall must treat that as unhealthy and
/// re-run the bootout/bootstrap path instead of silently no-oping.
#[cfg(target_os = "macos")]
fn is_launchd_service_active() -> bool {
    let label = "system/sh.emberlink.daemon";
    Command::new("launchctl")
        .args(["print", label])
        .output()
        .map(|out| {
            out.status.success()
                && launchd_service_has_active_process(&String::from_utf8_lossy(&out.stdout))
        })
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn launchd_service_has_active_process(print_output: &str) -> bool {
    let mut active_count: Option<u32> = None;
    let mut execs: Option<u32> = None;
    let mut state_xpcproxy = false;

    for line in print_output.lines() {
        let trimmed = line.trim();
        if let Some(count) = trimmed.strip_prefix("active count = ") {
            active_count = count.parse::<u32>().ok();
            continue;
        }
        if let Some(count) = trimmed.strip_prefix("execs = ") {
            execs = count.parse::<u32>().ok();
            continue;
        }
        if trimmed == "state = xpcproxy" {
            state_xpcproxy = true;
        }
    }

    active_count.is_some_and(|n| n > 0) && execs.is_some_and(|n| n > 0) && !state_xpcproxy
}

/// `launchctl bootout system <plist>` that tolerates the
/// "not-currently-bootstrapped" condition.
///
/// ## macOS-version-dependent exit surfaces
///
/// Apple surfaces the "service not loaded" condition differently across
/// macOS releases. Known shapes as of 2026-05-12:
///
/// | macOS version | exit code | stderr prefix |
/// |---|---|---|
/// | pre-macOS 26 | 113 | "Could not find specified service" |
/// | macOS 26+ (26.4 confirmed) | 5 | "Boot-out failed: 5: Input/output error" |
///
/// Both shapes mean "nothing was loaded — nothing to boot out." The
/// function tolerates both. **Future macOS releases may surface yet
/// another shape.** If you hit a new exit code here, add a row to the
/// table above, widen the tolerance check, and add a unit test for the
/// new case.
///
/// The exit-5 / EIO case is matched on BOTH exit code AND stderr prefix
/// to avoid swallowing unrelated I/O errors that happen to exit 5.
///
/// ## Testability
///
/// The inner logic is in [`bootout_tolerant_inner`] which accepts a
/// runner closure so unit tests can inject canned `(exit_code, stderr)`
/// tuples without spawning a real `launchctl` subprocess.
///
#[cfg(target_os = "macos")]
fn bootout_tolerant() -> Result<(), InstallError> {
    let cmd_string = format!("launchctl bootout system {LAUNCHD_PLIST_PATH}");
    bootout_tolerant_inner(&cmd_string, || {
        let output = Command::new("launchctl")
            .args(["bootout", "system", LAUNCHD_PLIST_PATH])
            .output()
            .map_err(|e| InstallError::Subprocess {
                cmd: cmd_string.clone(),
                stderr: format!("spawn failed: {e}"),
                exit_code: None,
            })?;
        let exit_code = output.status.code();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok((exit_code, stderr, output.status.success()))
    })
}

/// Inner logic for [`bootout_tolerant`], factored out so tests can inject
/// a mock runner without spawning a real subprocess.
///
/// `runner` returns `Ok((exit_code, stderr, success))` or an
/// `InstallError` if the process couldn't be spawned at all.
#[cfg(target_os = "macos")]
fn bootout_tolerant_inner<F>(cmd_string: &str, runner: F) -> Result<(), InstallError>
where
    F: FnOnce() -> Result<(Option<i32>, String, bool), InstallError>,
{
    let (exit_code, stderr, success) = runner()?;

    if success {
        return Ok(());
    }

    // Tolerate "not currently bootstrapped" — legacy surface (pre-macOS 26):
    // exit 113 or stderr containing "Could not find specified service".
    if exit_code == Some(113) || stderr.contains("Could not find specified service") {
        return Ok(());
    }

    // Tolerate macOS 26+ EIO surface: exit 5 + stderr prefix
    // "Boot-out failed: 5: Input/output error". Match on BOTH to avoid
    // swallowing unrelated EIO failures from launchd.
    if exit_code == Some(5) && stderr.starts_with("Boot-out failed: 5: Input/output error") {
        return Ok(());
    }

    tracing::warn!(
        cmd = %cmd_string,
        exit = exit_code.unwrap_or(-1),
        stderr = %stderr,
        "subprocess failed"
    );
    Err(InstallError::Subprocess {
        cmd: cmd_string.to_string(),
        stderr,
        exit_code,
    })
}

/// Standard error log path written into the launchd plist's `StandardErrorPath`.
/// launchd opens this file as root then reassigns file descriptors to the daemon
/// process — the file must exist and be writable by the `ember` uid **before**
/// `launchctl bootstrap` runs; otherwise launchd returns EX_CONFIG (78) and
/// KeepAlive respawns endlessly. See [`ensure_emberd_log_paths`].
#[cfg(target_os = "macos")]
const EMBERD_LOG_ERR: &str = "/var/log/emberd.err";

/// Standard output log path written into the launchd plist's `StandardOutPath`.
/// Same ownership requirement as [`EMBERD_LOG_ERR`].
#[cfg(target_os = "macos")]
const EMBERD_LOG_OUT: &str = "/var/log/emberd.out";

/// Pre-create `/var/log/emberd.err` and `/var/log/emberd.out` so launchd
/// can hand them to the `ember`-uid daemon process.
///
/// ## Why this step is necessary
///
/// The launchd plist sets `UserName=ember GroupName=ember-clients`, which means
/// launchd exec-s `emberd` as the `ember` system user with `ember-clients` as
/// its primary group. The plist also sets `StandardErrorPath=/var/log/emberd.err`
/// and `StandardOutPath=/var/log/emberd.out`. launchd opens those paths as
/// **root** at bootstrap time and passes the open file descriptors to the
/// daemon — but `/var/log` is `755 root:wheel`, so the `ember` user cannot
/// *create* those files. When the files don't exist, launchd fails with
/// `EX_CONFIG (78)`, KeepAlive fires, and the daemon never starts.
///
/// The fix: pre-create the files as root (this function runs under `sudo`) and
/// then chown them to `ember:ember-clients` so the daemon can append to them
/// at runtime.
///
#[cfg(target_os = "macos")]
pub fn ensure_emberd_log_paths() -> Result<bool, InstallError> {
    ensure_emberd_log_paths_inner(
        Path::new(EMBERD_LOG_ERR),
        Path::new(EMBERD_LOG_OUT),
        ember_user_uid_gid,
        |path, uid, gid| {
            use std::ffi::CString;
            let path_c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| {
                InstallError::Subprocess {
                    cmd: format!("chown {}", path.display()),
                    stderr: format!("path contains NUL: {e}"),
                    exit_code: None,
                }
            })?;
            // SAFETY: path_c is a valid NUL-terminated C string; uid/gid are
            // valid system-user values returned by getpwnam_r above.
            let rc = unsafe { libc::chown(path_c.as_ptr(), uid, gid) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(InstallError::Subprocess {
                    cmd: format!("chown {}:{} {}", uid, gid, path.display()),
                    stderr: format!("chown failed: {err}"),
                    exit_code: Some(rc),
                });
            }
            Ok(())
        },
    )
}

/// Look up the `ember` system user's numeric UID and GID via `getpwnam_r(3)`.
///
/// Returns `Some((uid, gid))` on success, `None` when the user does not exist.
#[cfg(target_os = "macos")]
fn ember_user_uid_gid() -> Option<(libc::uid_t, libc::gid_t)> {
    use std::ffi::CString;
    let cuser = CString::new("ember").ok()?;
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: zeroed passwd is a valid initial state for getpwnam_r.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: cuser outlives the call; buf and pwd are exclusively borrowed;
    // result is an out-parameter pointer.
    let rc = unsafe {
        libc::getpwnam_r(
            cuser.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some((pwd.pw_uid, pwd.pw_gid))
}

/// Inner logic for [`ensure_emberd_log_paths`], factored out so tests can
/// inject mock implementations of user lookup and chown without needing
/// root privileges or a real `ember` system user.
///
/// `lookup_uid_gid` returns `Some((uid, gid))` when the `ember` user exists,
/// `None` when it does not (tests inject the absent-user case with `|| None`).
///
/// `chown_file` applies ownership to a single path. Tests inject a closure
/// that records calls or checks path arguments; production injects `libc::chown`.
#[cfg(target_os = "macos")]
fn ensure_emberd_log_paths_inner<L, C>(
    err_path: &Path,
    out_path: &Path,
    lookup_uid_gid: L,
    mut chown_file: C,
) -> Result<bool, InstallError>
where
    L: FnOnce() -> Option<(libc::uid_t, libc::gid_t)>,
    C: FnMut(&Path, libc::uid_t, libc::gid_t) -> Result<(), InstallError>,
{
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Fail clearly when the ember user hasn't been provisioned yet.
    let (uid, gid) = lookup_uid_gid().ok_or_else(|| InstallError::Subprocess {
        cmd: "ensure_emberd_log_paths".to_string(),
        stderr: "ember system user does not exist — run `provision_ember_user` first".to_string(),
        exit_code: None,
    })?;

    let mut changed = false;
    for path in &[err_path, out_path] {
        let prior_meta = std::fs::metadata(path).ok();
        let prior_mode = prior_meta
            .as_ref()
            .map(|meta| meta.permissions().mode() & 0o777);
        let prior_owner = prior_meta.as_ref().map(|meta| (meta.uid(), meta.gid()));

        // Create the file if it doesn't exist; leave existing content intact
        // (truncate=false) so a running daemon's appended lines survive
        // an idempotent re-install.
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| InstallError::Subprocess {
                cmd: format!("touch {}", path.display()),
                stderr: format!("open/create failed: {e}"),
                exit_code: None,
            })?;

        // Mode 0644: daemon (ember uid) can append; world can read (useful for
        // operator `tail -f /var/log/emberd.err` without sudo).
        std::fs::set_permissions(path, Permissions::from_mode(0o644)).map_err(|e| {
            InstallError::Subprocess {
                cmd: format!("chmod 0644 {}", path.display()),
                stderr: format!("set_permissions failed: {e}"),
                exit_code: None,
            }
        })?;

        chown_file(path, uid, gid)?;

        if prior_meta.is_none() || prior_mode != Some(0o644) || prior_owner != Some((uid, gid)) {
            changed = true;
        }
    }

    Ok(changed)
}

/// Non-macOS fallback for [`install_launchd_plist`]. The launchd flow
/// is meaningful only on macOS; surface a clear error rather than
/// silently no-op.
#[cfg(not(target_os = "macos"))]
pub fn install_launchd_plist(_operator_home: &Path) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_launchd_plist".to_string(),
        stderr: "unsupported platform: launchd plist install is macOS-only".to_string(),
        exit_code: None,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn install_launchd_plist_with_trust_roots(
    _operator_home: &Path,
    _trust_roots: &str,
) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_launchd_plist_with_trust_roots".to_string(),
        stderr: "unsupported platform: launchd plist install is macOS-only".to_string(),
        exit_code: None,
    })
}

/// Install the `emberd.service` systemd unit at
/// `/etc/systemd/system/emberd.service` and enable it (per ADR 131
/// §Linux install).
///
/// **Idempotent.** `systemctl enable --now` exits 0 when the unit is
/// already enabled and active. If the on-disk unit already matches the
/// rendered body, the daemon-reload and enable steps are still issued
/// (cheap, idempotent) so a hand-edited active state always converges.
///
/// Steps:
/// - Write `SYSTEMD_UNIT_BODY` to `/etc/systemd/system/emberd.service`.
/// - `chmod 0644` the unit file.
/// - `systemctl daemon-reload`.
/// - `systemctl enable --now emberd.service`.
///
/// Requires root (typically invoked under `sudo` from the installer
/// entry point).
#[cfg(target_os = "linux")]
pub fn install_systemd_unit(operator_home: &Path) -> Result<(), InstallError> {
    // Publish the emberd binary first — the unit's ExecStart references
    // /usr/local/bin/emberd; without it `systemctl start` fails with
    // "Failed to locate executable" and the unit transitions to failed.
    install_emberd_binary()?;

    let path = Path::new(SYSTEMD_UNIT_PATH);
    let body = render_systemd_unit_body(operator_home);

    // Idempotency: only rewrite the unit file when the body differs.
    // We always run daemon-reload + enable --now so the active state
    // converges even if the unit file was hand-edited externally.
    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    if !already_matches {
        write_root_install_file_atomic(path, body.as_bytes())?;

        run("chmod", &["0644", SYSTEMD_UNIT_PATH], false)?;
    }

    run("systemctl", &["daemon-reload"], false)?;
    run("systemctl", &["enable", "--now", "emberd.service"], false)?;

    // ADR 155 SLICE 2b — stage (+ conditionally enable) the emberd-rpc sibling
    // alongside the core daemon. Errors propagate so a failed sibling stage
    // fails the install loudly rather than leaving a half-wired host.
    install_rpc_systemd_unit(operator_home)?;

    Ok(())
}

/// Non-Linux fallback for [`install_systemd_unit`]. The systemd flow
/// is meaningful only on Linux; surface a clear error rather than
/// silently no-op.
#[cfg(not(target_os = "linux"))]
pub fn install_systemd_unit(_operator_home: &Path) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_systemd_unit".to_string(),
        stderr: "unsupported platform: systemd unit install is Linux-only".to_string(),
        exit_code: None,
    })
}

/// Stage (and conditionally enable) the `emberd-rpc` sibling systemd unit
/// (ADR 155 SLICE 2b, "Option A" lifecycle).
///
/// `ember_rpc_sibling_bootstrap_landed` — install-lane entry point for the
/// `emberd-rpc` mTLS-frontend sibling (Linux).
///
/// Steps:
/// 1. Publish the platform binary to `/usr/local/bin/emberd-rpc-linux`.
/// 2. Render the unit with daemon system-path `EMBER_RPC_*` pins + carried
///    hardening and write it to `/etc/systemd/system/emberd-rpc.service`
///    (mode 0644) — ALWAYS, so the unit is ready the moment the bridge is on.
/// 3. `systemctl daemon-reload`.
/// 4. If the bridge is configured ON ([`rpc_sibling_should_bootstrap`]):
///    `systemctl enable --now emberd-rpc.service`. Else:
///    `systemctl disable --now emberd-rpc.service` (tolerant when the unit is
///    not loaded) so toggling the bridge off actually stops a previously-
///    enabled sibling (hard-right symmetry).
///
/// Requires root (typically invoked under `sudo` from the installer entry
/// point).
#[cfg(target_os = "linux")]
pub fn install_rpc_systemd_unit(operator_home: &Path) -> Result<(), InstallError> {
    // Publish the sibling binary first — the unit's ExecStart references
    // /usr/local/bin/emberd-rpc-linux; without it `systemctl start` fails
    // with "Failed to locate executable" and the unit goes to failed.
    install_emberd_rpc_binary()?;

    let path = Path::new(SYSTEMD_RPC_UNIT_PATH);
    let body = render_rpc_systemd_unit_body(operator_home);

    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    if !already_matches {
        write_root_install_file_atomic(path, body.as_bytes())?;
        run("chmod", &["0644", SYSTEMD_RPC_UNIT_PATH], false)?;
    }

    run("systemctl", &["daemon-reload"], false)?;

    if rpc_sibling_should_bootstrap(operator_home) {
        run(
            "systemctl",
            &["enable", "--now", "emberd-rpc.service"],
            false,
        )?;
        // `enable --now` on a Type=simple/Restart=always unit returns 0 as soon
        // as ExecStart is exec'd — BEFORE a cert-missing crash. Surface a
        // sibling that did not come up, but do NOT hard-fail: on a fresh
        // bridge-ON host emberd-core mints the rpc cert asynchronously, so the
        // sibling may legitimately be mid-restart and a strict check would
        // false-fail the install. WARN with a journal hint instead. (Added
        // after adversarial review, 2026-06-05.)
        let active = Command::new("systemctl")
            .args(["is-active", "--quiet", "emberd-rpc.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !active {
            tracing::warn!(
                "emberd-rpc sibling enabled but not yet active — if it does not \
                 settle shortly, check `journalctl -u emberd-rpc.service` (a \
                 missing rpc cert means emberd-core has not minted it yet)"
            );
        }
    } else {
        // Bridge OFF: stop + disable any previously-enabled sibling. We always
        // wrote the unit file above, so `disable --now` sees an existing unit;
        // on a unit that was never enabled it is a harmless exit-0 no-op. A
        // real failure (e.g. permission) still propagates.
        run(
            "systemctl",
            &["disable", "--now", "emberd-rpc.service"],
            false,
        )?;
    }

    Ok(())
}

/// Non-Linux fallback for [`install_rpc_systemd_unit`].
#[cfg(not(target_os = "linux"))]
pub fn install_rpc_systemd_unit(_operator_home: &Path) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_rpc_systemd_unit".to_string(),
        stderr: "unsupported platform: emberd-rpc systemd unit install is Linux-only".to_string(),
        exit_code: None,
    })
}

// ============================================================================
// ADR 155 Components 2 + 3 + MACOS-PRIMITIVES Decision 5 —
// spawn-helper + spawn-shim install integration.
// ============================================================================
//
// The spawn-helper is a root-privileged sibling daemon (LaunchDaemon
// on macOS, systemd unit on hardened Linux) that accepts
// SpawnDirective frames from the main `ember`-uid daemon over a UDS
// and performs setuid → chroot → sandbox/seccomp → exec. On macOS,
// the helper does NOT do the privileged setup directly (per MACOS-
// PRIMITIVES Decision 5): it `posix_spawn`s a tiny shim binary
// (`emberd-spawn-shim`) which performs the sandbox_init + chroot +
// setuid + execve dance in a fresh process image.
//
// Platform routing:
//   - macOS              → install_spawn_helper_plist() — LaunchDaemon
//                          + ALSO install_spawn_shim() — shim binary
//   - Hardened Linux     → install_spawn_helper_unit()  — systemd unit
//   - Modern Linux       → SKIP — in-daemon clone3 path handles spawn
//
// The detection-and-route decision lives in `broker::spawn_helper_
// client::should_use_spawn_helper()` (read once at process start;
// cached).

/// Where the spawn-helper LaunchDaemon plist lives on disk (macOS).
#[cfg(target_os = "macos")]
const SPAWN_HELPER_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.spawn-helper.plist";

/// Where the spawn-helper binaries are installed (macOS).
/// `/usr/local/libexec/` is the standard "system service binary not
/// on operator PATH" location.
#[cfg(target_os = "macos")]
const SPAWN_HELPER_BINARY_DIR: &str = "/usr/local/libexec";
#[cfg(target_os = "macos")]
const SPAWN_HELPER_BINARY_NAME: &str = "emberd-spawn-helper-macos";
#[cfg(target_os = "macos")]
const SPAWN_SHIM_BINARY_NAME: &str = "emberd-spawn-shim";

/// Path on disk for the hardened-Linux spawn-helper systemd unit.
#[cfg(target_os = "linux")]
pub const SPAWN_HELPER_UNIT_PATH: &str = "/etc/systemd/system/emberd-spawn-helper.service";

/// Path on disk for the installed spawn-helper binary on Linux.
#[cfg(target_os = "linux")]
pub const SPAWN_HELPER_LINUX_BIN_PATH: &str = "/usr/local/libexec/emberd-spawn-helper-linux";

// ─── Hardened-Linux: systemd unit ──────────────────────────────────

/// Detects whether the running Linux kernel is in "hardened" posture:
/// `kernel.unprivileged_userns_clone=0`. RHEL 8 ships this default;
/// AppArmor-hardened Ubuntu derivatives often set it.
///
/// Returns:
/// - `Ok(true)` — hardened kernel; spawn-helper install is required.
/// - `Ok(false)` — modern kernel; spawn-helper install must be
///   skipped.
/// - `Err` — the sysctl could not be read; surface to caller. Caller
///   should treat this as "hardened" (fail-closed).
#[cfg(target_os = "linux")]
pub fn detect_hardened_linux() -> Result<bool, InstallError> {
    const SYSCTL_PATH: &str = "/proc/sys/kernel/unprivileged_userns_clone";
    let raw = std::fs::read_to_string(SYSCTL_PATH).map_err(|e| InstallError::Subprocess {
        cmd: format!("read {SYSCTL_PATH}"),
        stderr: format!("{e}"),
        exit_code: None,
    })?;
    let trimmed = raw.trim();
    Ok(trimmed == "0")
}

/// Non-Linux stub. Other platforms have their own privilege-drop path
/// (macOS LaunchDaemon, modern Linux clone3) — the hardened-Linux
/// detection only applies on Linux.
#[cfg(not(target_os = "linux"))]
pub fn detect_hardened_linux() -> Result<bool, InstallError> {
    Ok(false)
}

/// Render the spawn-helper systemd unit body with `{{EMBER_UID}}`,
/// `{{POOL_UID_BASE}}`, and `{{POOL_SIZE}}` substituted. The template
/// lives at `infra/systemd/emberd-spawn-helper.service` as a
/// reference; this function emits the canonical production-shape body
/// in-code so the install path doesn't depend on disk-side template
/// files at deploy time.
///
/// Pool args are written into `ExecStart` per ADR 155 + the Decision
/// 5 brief: the helper bin REQUIRES `--pool-uid-base` and `--pool-
/// size` with no defaults; this renderer is the single producer of
/// those values for production systemd.
#[allow(dead_code)]
pub(crate) fn render_spawn_helper_unit_body(
    ember_uid: u32,
    pool_uid_base: u32,
    pool_size: u32,
) -> String {
    format!(
        "[Unit]\n\
         Description=Emberlink spawn-helper (hardened-Linux)\n\
         Documentation=https://docs.ember.link\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         Group=root\n\
         NoNewPrivileges=no\n\
         AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_SYS_CHROOT\n\
         CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_SYS_CHROOT\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         ReadWritePaths=/var/run /tmp/emberd-spawn-quarantine\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictNamespaces=true\n\
         RestrictRealtime=true\n\
         LockPersonality=true\n\
         MemoryDenyWriteExecute=true\n\
         RuntimeDirectory=emberd-spawn-helper\n\
         RuntimeDirectoryMode=0750\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StartLimitBurst=5\n\
         StartLimitIntervalSec=60\n\
         ExecStart=/usr/local/libexec/emberd-spawn-helper-linux --socket /var/run/emberd-spawn-helper.sock --daemon-uid {ember_uid} --pool-uid-base {pool_uid_base} --pool-size {pool_size}\n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=10\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Install the hardened-Linux spawn-helper systemd unit and enable
/// it.
///
/// `ember_uid` is the numeric uid of the main daemon (`ember`). The
/// helper enforces SO_PEERCRED uid matching this value at accept
/// time — incoming connections from any other uid are refused.
///
/// **Idempotent.** Re-running on a host with the unit already
/// installed rewrites only when the body differs; `daemon-reload` +
/// `enable --now` are always issued so the active state converges.
#[cfg(target_os = "linux")]
pub fn install_spawn_helper_unit(
    ember_uid: u32,
    pool_uid_base: u32,
    pool_size: u32,
) -> Result<(), InstallError> {
    let path = Path::new(SPAWN_HELPER_UNIT_PATH);
    let body = render_spawn_helper_unit_body(ember_uid, pool_uid_base, pool_size);

    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    if !already_matches {
        write_root_install_file_atomic(path, body.as_bytes())?;

        run("chmod", &["0644", SPAWN_HELPER_UNIT_PATH], false)?;
    }

    run("systemctl", &["daemon-reload"], false)?;
    run(
        "systemctl",
        &["enable", "--now", "emberd-spawn-helper.service"],
        false,
    )?;

    Ok(())
}

/// Non-Linux fallback. The hardened-Linux helper unit is meaningful
/// only on Linux; other platforms have their own privilege-drop path.
#[cfg(not(target_os = "linux"))]
pub fn install_spawn_helper_unit(
    _ember_uid: u32,
    _pool_uid_base: u32,
    _pool_size: u32,
) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_spawn_helper_unit".to_string(),
        stderr: "unsupported platform: spawn-helper systemd unit is Linux-only".to_string(),
        exit_code: None,
    })
}

// ─── macOS: LaunchDaemon plist + shim binary ───────────────────────

/// Probe the `ember-clients` connect group via `getgrnam_r`. Returns
/// `true` when the group exists.
///
/// The spawn-helper's UDS lives at `0660 root:ember-clients` —
/// without the group, the daemon's `ember` uid cannot connect. The
/// install path refuses to write the plist when this probe fails.
#[cfg(target_os = "macos")]
fn ember_clients_group_exists() -> bool {
    let Ok(c_name) = std::ffi::CString::new("ember-clients") else {
        return false;
    };
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: grp + result are out-params; getgrnam_r fills them on
    // success.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: c_name is valid; buf is writable.
    let rc = unsafe {
        libc::getgrnam_r(
            c_name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    rc == 0 && !result.is_null()
}

/// Render the spawn-helper LaunchDaemon plist body, substituting:
/// - `{{EMBER_UID}}` → numeric uid of the `ember` system user
/// - `{{POOL_UID_BASE}}` → first uid in the spawn-helper pool
/// - `{{POOL_SIZE}}` → number of slots in the pool
/// - `{{EXPECTED_SHIM_HASH}}` → blake3 hex of the shipped shim
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn render_spawn_helper_plist_body(
    ember_uid: u32,
    pool_uid_base: u32,
    pool_size: u32,
    expected_shim_hash: &str,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n  \
           <key>Label</key>           <string>sh.emberlink.spawn-helper</string>\n  \
           <key>UserName</key>        <string>root</string>\n  \
           <key>GroupName</key>       <string>ember-clients</string>\n  \
           <key>ProgramArguments</key>\n  \
           <array>\n    \
             <string>/usr/local/libexec/emberd-spawn-helper-macos</string>\n    \
             <string>--socket</string>\n    \
             <string>/var/run/emberd-spawn-helper.sock</string>\n    \
             <string>--daemon-uid</string>\n    \
             <string>{ember_uid}</string>\n    \
             <string>--pool-uid-base</string>\n    \
             <string>{pool_uid_base}</string>\n    \
             <string>--pool-size</string>\n    \
             <string>{pool_size}</string>\n    \
             <string>--shim-path</string>\n    \
             <string>/usr/local/libexec/emberd-spawn-shim</string>\n  \
           </array>\n  \
           <key>EnvironmentVariables</key>\n  \
           <dict>\n    \
             <key>EXPECTED_SHIM_HASH</key>\n    \
             <string>{expected_shim_hash}</string>\n  \
           </dict>\n  \
           <key>KeepAlive</key>       <true/>\n  \
           <key>RunAtLoad</key>       <true/>\n  \
           <key>StandardErrorPath</key><string>/var/log/emberd-spawn-helper.err</string>\n  \
           <key>StandardOutPath</key> <string>/var/log/emberd-spawn-helper.out</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Install the `sh.emberlink.spawn-helper` LaunchDaemon, the
/// `emberd-spawn-helper-macos` binary, and the
/// `emberd-spawn-shim` binary; bootstrap the LaunchDaemon into the
/// system domain.
///
/// **Idempotent.** Skips the bootout/bootstrap cycle when the on-disk
/// plist matches AND the service is currently loaded.
///
/// Steps:
/// 1. Verify the `ember-clients` connect group exists (the plist
///    sets `GroupName=ember-clients`; an absent group would block
///    daemon connectivity).
/// 2. Resolve the `ember` system uid.
/// 3. Verify both the helper binary and the shim binary are present at
///    `/usr/local/libexec/` (placed by the install lane / `.pkg` payload)
///    and normalize their mode to 0755.
/// 4. Compute blake3 of the on-disk shim; render it into the plist's
///    `EXPECTED_SHIM_HASH` env var.
/// 5. Pre-create `/var/log/emberd-spawn-helper.{err,out}` for
///    launchd's fd handoff.
/// 6. Write the plist (mode 0644), `launchctl bootout`-tolerant,
///    `launchctl bootstrap system`.
#[cfg(target_os = "macos")]
pub fn install_spawn_helper_plist(pool_uid_base: u32, pool_size: u32) -> Result<(), InstallError> {
    // 1) Probe ember-clients group. Refuse install if missing — the
    //    plist's GroupName=ember-clients would land on a non-
    //    existent group and the helper's socket would inherit gid
    //    0 (wheel), blocking the daemon's connect(2).
    if !ember_clients_group_exists() {
        return Err(InstallError::Subprocess {
            cmd: "getgrnam_r(ember-clients)".to_string(),
            stderr: "the `ember-clients` connect group is not provisioned — \
                     run `sudo ember daemon install` (or `provision_ember_user`) first"
                .to_string(),
            exit_code: None,
        });
    }

    // 2) Resolve ember uid.
    let (ember_uid, _ember_gid) = ember_user_uid_gid().ok_or_else(|| InstallError::Subprocess {
        cmd: "getpwnam_r ember".to_string(),
        stderr: "the `ember` system user is not provisioned — run \
                 `sudo ember daemon install` (or `provision_ember_user`) first"
            .to_string(),
        exit_code: None,
    })?;

    // 3) Verify helper binary + shim binary are present at /usr/local/libexec
    //    (placed by the install lane / .pkg payload) and normalize perms.
    install_spawn_helper_binary()?;
    let shim_dest = install_spawn_shim_binary()?;

    // 4) Compute on-disk shim hash for the plist env var.
    let shim_hash = ember_spawn_helper::hash::blake3_hex_of_file(&shim_dest).map_err(|e| {
        InstallError::Subprocess {
            cmd: format!("blake3 {}", shim_dest.display()),
            stderr: format!("hash failed: {e}"),
            exit_code: None,
        }
    })?;

    let path = Path::new(SPAWN_HELPER_PLIST_PATH);
    let body = render_spawn_helper_plist_body(ember_uid, pool_uid_base, pool_size, &shim_hash);

    let already_matches = std::fs::read_to_string(path)
        .map(|existing| existing == body)
        .unwrap_or(false);

    if !already_matches || !is_spawn_helper_service_loaded() {
        write_root_install_file_atomic(path, body.as_bytes())?;
        run("chmod", &["0644", SPAWN_HELPER_PLIST_PATH], false)?;

        spawn_helper_bootout_tolerant()?;

        ensure_spawn_helper_log_paths()?;

        run(
            "launchctl",
            &["bootstrap", "system", SPAWN_HELPER_PLIST_PATH],
            false,
        )?;
    }

    Ok(())
}

/// Non-macOS fallback for [`install_spawn_helper_plist`].
#[cfg(not(target_os = "macos"))]
pub fn install_spawn_helper_plist(
    _pool_uid_base: u32,
    _pool_size: u32,
) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_spawn_helper_plist".to_string(),
        stderr: "unsupported platform: spawn-helper LaunchDaemon is macOS-only \
                 (Linux hardened variant lives in install_spawn_helper_unit)"
            .to_string(),
        exit_code: None,
    })
}

/// True iff `launchctl print system/sh.emberlink.spawn-helper` exits
/// 0 (service is currently loaded into the system domain).
#[cfg(target_os = "macos")]
fn is_spawn_helper_service_loaded() -> bool {
    let label = "system/sh.emberlink.spawn-helper";
    Command::new("launchctl")
        .args(["print", label])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// `launchctl bootout system <plist>` that tolerates "not currently
/// bootstrapped" the same way `bootout_tolerant` does for the main
/// daemon plist.
#[cfg(target_os = "macos")]
fn spawn_helper_bootout_tolerant() -> Result<(), InstallError> {
    let cmd_string = format!("launchctl bootout system {SPAWN_HELPER_PLIST_PATH}");
    bootout_tolerant_inner(&cmd_string, || {
        let output = Command::new("launchctl")
            .args(["bootout", "system", SPAWN_HELPER_PLIST_PATH])
            .output()
            .map_err(|e| InstallError::Subprocess {
                cmd: cmd_string.clone(),
                stderr: format!("spawn failed: {e}"),
                exit_code: None,
            })?;
        let exit_code = output.status.code();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok((exit_code, stderr, output.status.success()))
    })
}

/// Verify the `emberd-spawn-helper-macos` binary is present at
/// `/usr/local/libexec/` (placed by the install lane / `.pkg` payload) and
/// normalize its mode to `0755`. Idempotent.
///
/// The helper is mode `0755 root:wheel`. It's NOT setuid (per ADR
/// 155 Component 4) — launchd starts it as root via
/// `UserName=root`.
#[cfg(target_os = "macos")]
fn install_spawn_helper_binary() -> Result<(), InstallError> {
    install_libexec_binary(SPAWN_HELPER_BINARY_NAME)?;
    Ok(())
}

/// Verify the `emberd-spawn-shim` binary is present at `/usr/local/libexec/`
/// (placed by the install lane / `.pkg` payload) and normalize its mode to
/// `0755 root:wheel`. NOT setuid — the shim receives its root
/// identity through the helper's `posix_spawn` (which runs the shim
/// in a clean post-execve image inheriting the helper's effective
/// uid), not via a kernel-evaluated suid bit.
///
/// Returns the install destination so the caller can hash it for
/// `EXPECTED_SHIM_HASH`.
#[cfg(target_os = "macos")]
fn install_spawn_shim_binary() -> Result<PathBuf, InstallError> {
    install_libexec_binary(SPAWN_SHIM_BINARY_NAME)
}

/// Verify a privilege-separation binary is present at
/// `/usr/local/libexec/<name>` and normalize its mode to `0755`; return its
/// path.
///
/// The helper + shim are placed at `/usr/local/libexec/` by the install lane
/// (`scripts/dev-refresh-macos-host-install.sh`) or the signed `.pkg` payload —
/// NOT copied from the running CLI's directory. The `ember` CLI lives inside a
/// sealed, codesigned `.app` bundle (`/usr/local/lib/ember.app/Contents/MacOS`),
/// so the old `current_exe().parent()` source could neither hold these binaries
/// (adding files breaks the bundle seal) nor be a stable source. The
/// authoritative home is the libexec dir the plist already references.
///
/// Returns a clear error if the lane has not placed the binary yet — that is a
/// loud guard rail, not a copy fallback.
#[cfg(target_os = "macos")]
fn install_libexec_binary(name: &str) -> Result<PathBuf, InstallError> {
    let dest = Path::new(SPAWN_HELPER_BINARY_DIR).join(name);

    if !dest.exists() {
        return Err(InstallError::Subprocess {
            cmd: format!("locate {name}"),
            stderr: format!(
                "{name} not found at {} — the install lane (`./x insiders` or the \
                 signed .pkg) must place it there before `ember daemon install` \
                 renders the spawn-helper plist",
                dest.display()
            ),
            exit_code: None,
        });
    }

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
        InstallError::Subprocess {
            cmd: format!("chmod 0755 {}", dest.display()),
            stderr: format!("set_permissions failed: {e}"),
            exit_code: None,
        }
    })?;

    Ok(dest)
}

/// Pre-create `/var/log/emberd-spawn-helper.{err,out}` so launchd's
/// fd handoff succeeds at bootstrap.
#[cfg(target_os = "macos")]
fn ensure_spawn_helper_log_paths() -> Result<(), InstallError> {
    for path in &[
        "/var/log/emberd-spawn-helper.err",
        "/var/log/emberd-spawn-helper.out",
    ] {
        if !Path::new(path).exists() {
            std::fs::File::create(path).map_err(|e| InstallError::Subprocess {
                cmd: format!("create {path}"),
                stderr: format!("create failed: {e}"),
                exit_code: None,
            })?;
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).map_err(|e| {
            InstallError::Subprocess {
                cmd: format!("chmod 0644 {path}"),
                stderr: format!("set_permissions failed: {e}"),
                exit_code: None,
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T1 unit — `already_exists` tolerates every shape macOS / Linux
    /// emit when an `-o create` lands on an existing record. Per the
    /// table in `already_exists`'s doc-comment.
    #[test]
    fn already_exists_recognises_all_known_shapes() {
        // Pre-macOS 26 + Linux groupadd/useradd
        assert!(already_exists("group ember already exists"));
        assert!(already_exists("user already a member of ember-clients"));
        // macOS 26+ dseditgroup
        assert!(already_exists(
            "Operation cancelled because record could not be replaced"
        ));
        // Case-insensitive (helper lowercases before matching)
        assert!(already_exists(
            "OPERATION CANCELLED BECAUSE RECORD COULD NOT BE REPLACED"
        ));
        // Negatives — real failures must NOT be tolerated
        assert!(!already_exists("permission denied"));
        assert!(!already_exists("dseditgroup: command not found"));
        assert!(!already_exists(""));
    }

    #[test]
    #[cfg(unix)]
    fn write_root_install_file_atomic_replaces_symlink_without_clobbering_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        let dest = tmp.path().join("launchd.plist");
        std::fs::write(&target, b"keep-target").expect("write target");
        symlink(&target, &dest).expect("create symlink");

        write_root_install_file_atomic(&dest, b"new-unit").expect("atomic write");

        assert_eq!(std::fs::read(&target).expect("read target"), b"keep-target");
        assert_eq!(std::fs::read(&dest).expect("read dest"), b"new-unit");
        assert!(
            !std::fs::symlink_metadata(&dest)
                .expect("dest metadata")
                .file_type()
                .is_symlink(),
            "atomic install write must replace the destination symlink itself"
        );
    }

    #[test]
    #[cfg(unix)]
    fn copy_root_credential_file_atomic_replaces_symlink_without_clobbering_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("source.pem");
        let target = tmp.path().join("target");
        let dest = tmp.path().join("credential.pem");
        std::fs::write(&src, b"new-secret").expect("write source");
        std::fs::write(&target, b"keep-target").expect("write target");
        symlink(&target, &dest).expect("create symlink");

        copy_root_credential_file_atomic(&src, &dest).expect("atomic credential copy");

        assert_eq!(std::fs::read(&target).expect("read target"), b"keep-target");
        assert_eq!(std::fs::read(&dest).expect("read dest"), b"new-secret");
        assert!(
            !std::fs::symlink_metadata(&dest)
                .expect("dest metadata")
                .file_type()
                .is_symlink(),
            "atomic credential copy must replace the destination symlink itself"
        );
        assert_eq!(
            std::fs::metadata(&dest)
                .expect("dest metadata")
                .permissions()
                .mode()
                & 0o777,
            0o440,
            "credential copy must pre-lock the destination mode"
        );
    }

    /// T1 unit — the chown traversal is a no-op when the system state
    /// root does not exist yet (fresh host pre-install). The public
    /// `chown_ember_data_dirs` short-circuits on a missing root so
    /// re-running before the installer has populated the system tree is
    /// safe. Legacy binary-manifest repair is migration-only and not part
    /// of this default chown path.
    #[test]
    fn chown_ember_data_dirs_on_empty_system_root_is_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Production resolver targets a real `/Library/Application Support/
        // Emberlink/`; under a non-root test runner that path either
        // doesn't exist (no-op) or is unreadable. The function is
        // expected to return Ok in both cases.
        let result = chown_ember_data_dirs(tmp.path());
        // The only error we tolerate is a chown/chmod shell-out failure
        // (we're not root and the `ember:ember-clients` identity doesn't
        // exist in CI); fs reads of a missing system tree return Ok via
        // the early-return in `chown_ember_data_dirs_inner`.
        match result {
            Ok(()) => {}
            Err(InstallError::Subprocess { cmd, .. })
                if cmd.starts_with("chown ") || cmd.starts_with("chmod ") => {}
            Err(other) => panic!("unexpected error from chown_ember_data_dirs: {other:?}"),
        }
    }

    /// T1 — chown_ember_data_dirs_inner walks the daemon's system state
    /// root and visits every entry recursively (per ADR 218). The walk
    /// is unconditional — there are no operator-data exceptions inside
    /// the system tree because ADR 218 moved orchestrator.lock /
    /// shadow/ / binaries/ out of the daemon tree entirely.
    ///
    /// Uses closure injection + tempdir-as-state-root so no root
    /// privileges or real system paths are required.
    #[test]
    fn chown_ember_data_dirs_inner_visits_daemon_state_recursively() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_root = tmp.path();

        // Populate the system state root with the directories the daemon
        // creates at runtime: data/, run/, sessions/, codex-sessions/,
        // locks/, scratch/. plus a SQLite event-store file.
        let data_dir = state_root.join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data");
        std::fs::write(data_dir.join("ember.db"), b"fake-sqlite-header").expect("write ember.db");
        std::fs::write(data_dir.join("ember.db-wal"), b"fake-wal").expect("write ember.db-wal");
        for name in ["run", "sessions", "codex-sessions", "locks", "scratch"] {
            std::fs::create_dir_all(state_root.join(name)).expect("mkdir runtime subdir");
        }

        let mut visited: Vec<std::path::PathBuf> = Vec::new();
        chown_ember_data_dirs_inner(state_root, &mut |path, _is_dir| {
            visited.push(path.to_path_buf());
            Ok(())
        })
        .expect("walk must succeed");

        // The state root itself MUST be visited (chowned to
        // ember:ember-clients).
        assert!(
            visited.contains(&state_root.to_path_buf()),
            "state_root must be visited; visited={visited:?}"
        );
        // data/ + its files must be visited.
        for path in [
            data_dir.clone(),
            data_dir.join("ember.db"),
            data_dir.join("ember.db-wal"),
        ] {
            assert!(
                visited.contains(&path),
                "{} not visited; visited={visited:?}",
                path.display()
            );
        }
        // Every runtime subdir must be visited.
        for name in ["run", "sessions", "codex-sessions", "locks", "scratch"] {
            let path = state_root.join(name);
            assert!(
                visited.contains(&path),
                "{}/ not visited; visited={visited:?}",
                path.display()
            );
        }
    }

    /// T1 — `chown_ember_data_dirs_inner` is a no-op when the state root
    /// does not exist. This is the fresh-host posture before the
    /// installer has populated `/Library/Application Support/Emberlink/`.
    #[test]
    fn chown_ember_data_dirs_inner_missing_state_root_is_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let absent_root = tmp.path().join("does-not-exist");

        let mut visited: Vec<std::path::PathBuf> = Vec::new();
        chown_ember_data_dirs_inner(&absent_root, &mut |path, _is_dir| {
            visited.push(path.to_path_buf());
            Ok(())
        })
        .expect("missing root must be a no-op");

        assert!(
            visited.is_empty(),
            "missing state root must NOT invoke the closure; visited={visited:?}"
        );
    }

    /// T1 — `chown_chmod_recursive_inner` skips symlink entries entirely
    /// so a dangling symlink under the daemon's system state root does
    /// not surface as a chown-of-nothing error. The walk follows
    /// non-symlink directory entries normally.
    #[test]
    fn chown_ember_data_dirs_skips_dangling_symlink_entries() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let state_root = tmp.path();
        let sub_dir = state_root.join("scratch");
        std::fs::create_dir_all(&sub_dir).expect("mkdir scratch");
        let symlink_path = sub_dir.join("orphan");
        #[cfg(unix)]
        symlink("/nonexistent/ember-target", &symlink_path).expect("create dangling symlink");

        let mut visited: Vec<std::path::PathBuf> = Vec::new();
        let result = chown_ember_data_dirs_inner(state_root, &mut |path, _is_dir| {
            visited.push(path.to_path_buf());
            Ok(())
        });
        assert!(
            result.is_ok(),
            "chown_ember_data_dirs_inner must ignore dangling symlinks, got: {result:?}"
        );
        // Containing dir + state root are visited; the dangling symlink itself is NOT.
        assert!(
            visited.contains(&sub_dir),
            "containing dir must be visited; visited={visited:?}"
        );
        assert!(
            !visited.contains(&symlink_path),
            "dangling symlink entry must be skipped; visited={visited:?}"
        );
    }

    /// Integration-tier — exercises the real `provision_ember_user`
    /// path. Requires sudo + a clean macOS/Linux host, mutates system
    /// state (creates a real system user + group), so it is `#[ignore]`
    /// by default. Un-ignore when running the installer integration
    /// suite on a disposable VM. The assertion is that a second call
    /// returns `Ok(())` — i.e. provisioning is idempotent.
    #[test]
    #[ignore = "requires sudo + mutates system users; run only in installer integration suite"]
    fn provision_ember_user_idempotent_on_second_call() {
        provision_ember_user().expect("first call");
        provision_ember_user().expect("second call must be a no-op");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn clear_stale_launchd_runtime_artifacts_removes_pid_and_socket() {
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().expect("tempdir");
        // Drive the inner helper with a `for_test` DaemonPaths so the
        // walk targets `<tmp>/run/...` instead of the real system path.
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.run_dir).expect("mkdir run dir");

        let pid_path = paths.run_dir.join("emberd.pid");
        std::fs::write(&pid_path, b"12345\n").expect("write pid file");

        let sock_path = paths.run_dir.join("daemon.sock");
        let _listener = UnixListener::bind(&sock_path).expect("bind daemon.sock");

        let changed =
            clear_stale_launchd_runtime_artifacts_inner(&paths).expect("cleanup must succeed");

        assert!(
            !pid_path.exists(),
            "stale pid file must be removed before bootstrap"
        );
        assert!(
            !sock_path.exists(),
            "stale daemon socket must be removed before bootstrap"
        );
        assert!(
            changed,
            "cleanup must report when stale artifacts were removed"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn clear_stale_launchd_runtime_artifacts_false_when_nothing_to_remove() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.run_dir).expect("mkdir run dir");

        let changed =
            clear_stale_launchd_runtime_artifacts_inner(&paths).expect("cleanup must succeed");

        assert!(
            !changed,
            "cleanup must report false when no stale runtime artifacts existed"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn wait_for_launchd_runtime_artifacts_inner_succeeds_once_probe_turns_true() {
        let attempts = std::cell::Cell::new(0usize);
        let sleeps = std::cell::Cell::new(0usize);

        wait_for_launchd_runtime_artifacts_inner(
            5,
            || {
                let next = attempts.get() + 1;
                attempts.set(next);
                next >= 3
            },
            || sleeps.set(sleeps.get() + 1),
            || "unused diagnostics".to_string(),
        )
        .expect("probe should eventually succeed");

        assert_eq!(attempts.get(), 3, "probe should stop once artifacts appear");
        assert_eq!(
            sleeps.get(),
            2,
            "sleep should run only between failed probes"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn wait_for_launchd_runtime_artifacts_inner_times_out_when_probe_stays_false() {
        let attempts = std::cell::Cell::new(0usize);
        let sleeps = std::cell::Cell::new(0usize);

        let err = wait_for_launchd_runtime_artifacts_inner(
            4,
            || {
                attempts.set(attempts.get() + 1);
                false
            },
            || sleeps.set(sleeps.get() + 1),
            || "launchctl diagnostic payload".to_string(),
        )
        .expect_err("probe should time out");

        match err {
            InstallError::Subprocess { stderr, .. } => {
                assert!(
                    stderr.contains("runtime artifacts never reappeared"),
                    "unexpected timeout stderr: {stderr}"
                );
                assert!(
                    stderr.contains("launchctl diagnostic payload"),
                    "timeout stderr must include diagnostics: {stderr}"
                );
            }
            other => panic!("expected subprocess timeout error, got {other:?}"),
        }
        assert_eq!(attempts.get(), 4, "probe count should match max attempts");
        assert_eq!(
            sleeps.get(),
            3,
            "sleep should not run after the final attempt"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn park_incompatible_launchd_binary_manifest_inner_moves_manifest_and_sidecar() {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest_path = tmp.path().join("manifest.toml");
        let sidecar_path = manifest_path.with_extension("toml.sig");
        let manifest_bytes = b"[[entries]]\ntool_name = \"ember-gh\"\n";
        std::fs::write(&manifest_path, manifest_bytes).expect("write manifest");

        let dev_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let release_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let sig = dev_key.sign(manifest_bytes);
        let sidecar = serde_json::json!({
            "schema_version": 1,
            "signature": format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
            ),
            "signature_alg": "ed25519",
        });
        std::fs::write(&sidecar_path, sidecar.to_string()).expect("write sidecar");

        let changed = park_incompatible_launchd_binary_manifest_inner(
            &manifest_path,
            &[release_key.verifying_key()],
            "test",
        )
        .expect("incompatible manifest should be parked");

        assert!(changed, "parking should report a changed manifest");
        assert!(
            !manifest_path.exists(),
            "original manifest should move out of launchd's startup path"
        );
        assert!(
            !sidecar_path.exists(),
            "original sidecar should move with the manifest"
        );
        assert!(
            tmp.path().join("manifest.toml.rejected-test").exists(),
            "parked manifest must preserve the original bytes"
        );
        assert!(
            tmp.path().join("manifest.toml.sig.rejected-test").exists(),
            "parked sidecar must preserve the original signature"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn park_incompatible_launchd_binary_manifest_inner_keeps_valid_manifest() {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest_path = tmp.path().join("manifest.toml");
        let sidecar_path = manifest_path.with_extension("toml.sig");
        let manifest_bytes = b"[[entries]]\ntool_name = \"ember-gh\"\n";
        std::fs::write(&manifest_path, manifest_bytes).expect("write manifest");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let sig = signing_key.sign(manifest_bytes);
        let sidecar = serde_json::json!({
            "schema_version": 1,
            "signature": format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
            ),
            "signature_alg": "ed25519",
        });
        std::fs::write(&sidecar_path, sidecar.to_string()).expect("write sidecar");

        let changed = park_incompatible_launchd_binary_manifest_inner(
            &manifest_path,
            &[signing_key.verifying_key()],
            "test",
        )
        .expect("valid manifest should be kept");

        assert!(!changed, "valid manifest should not be parked");
        assert!(manifest_path.exists(), "original manifest must remain");
        assert!(sidecar_path.exists(), "original sidecar must remain");
        assert!(
            !tmp.path().join("manifest.toml.rejected-test").exists(),
            "no rejected copy should be created"
        );
    }

    /// T1 — under Plan 2A, `provision_se_mek_inner` creates the data
    /// dir, chowns it to `ember:ember-clients` (when root), and DELETES
    /// any orphaned legacy `vault-mek.bin` from earlier SE-attempt
    /// installs. The MEK now lives in `/Library/Keychains/System.
    /// keychain`, not on disk. Under non-root test runners the
    /// System.keychain write is skipped.
    ///
    /// Post-ADR-218 the data dir lives at the system path; the test
    /// uses `DaemonPaths::for_test(tmp)` so the inner helper writes
    /// under a tempdir instead of `/Library/Application Support/
    /// Emberlink/`.
    #[test]
    fn provision_se_mek_inner_creates_data_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        let result = provision_se_mek_inner(&paths);

        assert!(
            paths.data_dir.is_dir(),
            "data dir must be created; provision_se_mek_inner returned {result:?}"
        );

        // `vault-mek.bin` MUST NOT exist after install — Plan 2A stores
        // the MEK in System.keychain instead.
        let mek_path = paths.data_dir.join("vault-mek.bin");
        assert!(
            !mek_path.exists(),
            "vault-mek.bin must NOT exist after install (Plan 2A — MEK is in System.keychain)"
        );

        // Non-root runners may hit chown/chmod failures (no `ember`
        // user in CI). Only those errors are tolerated.
        match result {
            Ok(()) => {}
            Err(InstallError::Subprocess { cmd, .. })
                if cmd.starts_with("chown ") || cmd.starts_with("chmod ") => {}
            Err(other) => panic!(
                "unexpected error from provision_se_mek_inner (only chown/chmod failures expected under non-root): {other:?}"
            ),
        }
    }

    /// T1 — `provision_se_mek_inner` cleans up legacy `vault-mek.bin`
    /// blobs from earlier SE-attempt installs. The pre-existing blob is
    /// the product of a previous failed install lineage and is no
    /// longer read by the daemon under Plan 2A.
    #[test]
    fn provision_se_mek_inner_idempotent_no_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());

        // Pre-create the data dir + a stale legacy blob.
        std::fs::create_dir_all(&paths.data_dir).expect("mkdir data");
        let mek_path = paths.data_dir.join("vault-mek.bin");
        let checkpoint = [0xABu8; 32];
        std::fs::write(&mek_path, checkpoint).expect("write checkpoint");

        let result = provision_se_mek_inner(&paths);
        match result {
            Ok(()) => {}
            Err(InstallError::Subprocess { cmd, .. })
                if cmd.starts_with("chown ") || cmd.starts_with("chmod ") => {}
            Err(other) => panic!("unexpected error on idempotent path: {other:?}"),
        }

        // Plan 2A cleans up the legacy blob.
        assert!(
            !mek_path.exists(),
            "Plan 2A install must remove the legacy vault-mek.bin orphan"
        );
    }

    /// Per ADR 218 (2026-06-14) the launchd plist body MUST NOT bake
    /// `HOME=<operator_home>` into `EnvironmentVariables` — the daemon
    /// resolves its paths exclusively via
    /// `crate::paths::DaemonPaths::system()` and never reads from
    /// `$HOME`. The plist still pins `EMBER_APP_PEM_PATH` /
    /// `EMBER_APP_ENV_PATH` (those point at `/etc/emberlink/`, a
    /// system path ADR 218 does not move). Guards against silent drift
    /// between the rendered text and ADR 218.
    ///
    /// Build the expected text by joining lines with `\n` rather than
    /// using string-continuation (`\\\n`), which would collapse the
    /// significant two-space indentation inside `<dict>...</dict>`.
    #[test]
    fn plist_body_matches_adr_218() {
        let expected = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
            "<plist version=\"1.0\">",
            "<dict>",
            "  <key>Label</key>           <string>sh.emberlink.daemon</string>",
            "  <key>UserName</key>        <string>ember</string>",
            "  <key>GroupName</key>       <string>ember-clients</string>",
            "  <key>EnvironmentVariables</key>",
            "  <dict>",
            "    <key>EMBER_APP_PEM_PATH</key><string>/etc/emberlink/ember-engine-app.pem</string>",
            "    <key>EMBER_APP_ENV_PATH</key><string>/etc/emberlink/ember-engine.env</string>",
            "  </dict>",
            // emberd_launchd_sandbox_wired.
            "  <!-- emberd_launchd_sandbox_wired — sandbox-exec wrap per META-DAEMON-SECCOMP-PROFILE-HOST. -->",
            "  <key>ProgramArguments</key>",
            "  <array>",
            "    <string>/usr/bin/sandbox-exec</string>",
            "    <string>-f</string>",
            "    <string>/usr/local/lib/ember/sandbox/emberd.sb</string>",
            "    <string>/usr/local/bin/emberd</string>",
            "    <string>--foreground</string>",
            "  </array>",
            "  <key>KeepAlive</key>       <true/>",
            "  <key>RunAtLoad</key>       <true/>",
            "  <key>StandardErrorPath</key><string>/var/log/emberd.err</string>",
            "  <key>StandardOutPath</key> <string>/var/log/emberd.out</string>",
            "</dict>",
            "</plist>",
            "",
        ]
        .join("\n");
        assert_eq!(
            render_launchd_plist_body(Path::new("/home/test-operator")),
            expected
        );
        // Regression guard: the plist must NOT bake HOME any more
        // (the daemon no longer resolves paths through $HOME).
        assert!(
            !render_launchd_plist_body(Path::new("/home/test-operator"))
                .contains("<key>HOME</key>"),
            "plist must NOT bake HOME per ADR 218"
        );
    }

    /// When trust roots are passed in, the rendered plist must include an
    /// `EMBER_TRUST_ROOTS` env entry in the EnvironmentVariables dict — the
    /// daemon reads this at startup to assemble the manifest trust set
    /// (ADR 157 §Component 1). The non-trust-roots path is exercised by
    /// `plist_body_matches_adr_131`; this test is the load-bearing positive
    /// case.
    #[test]
    fn plist_body_with_trust_roots_emits_env_entry() {
        let pubkey_hex = "a".repeat(64);
        let body = render_launchd_plist_body_with_trust_roots(
            Path::new("/home/test-operator"),
            &pubkey_hex,
        );
        assert!(
            body.contains(&format!(
                "<key>EMBER_TRUST_ROOTS</key><string>{pubkey_hex}</string>"
            )),
            "trust-roots plist must embed EMBER_TRUST_ROOTS entry; got: {body}"
        );
        // The entry must land INSIDE the EnvironmentVariables <dict>, not
        // outside — ahead of </dict> + ProgramArguments.
        let env_close = body.find("</dict>").expect("env dict close must exist");
        let trust_pos = body
            .find("EMBER_TRUST_ROOTS")
            .expect("trust entry must exist");
        assert!(
            trust_pos < env_close,
            "EMBER_TRUST_ROOTS must precede the env </dict>"
        );
    }

    /// Empty trust_roots is the legacy posture — the rendered body must
    /// match `render_launchd_plist_body(...)` exactly so existing hosts
    /// installed without trust roots see no churn.
    #[test]
    fn plist_body_empty_trust_roots_matches_legacy_body() {
        let home = Path::new("/home/test-operator");
        assert_eq!(
            render_launchd_plist_body_with_trust_roots(home, ""),
            render_launchd_plist_body(home),
        );
    }

    /// Per ADR 218 (2026-06-14) the systemd unit body MUST NOT bake
    /// `Environment=HOME=<operator_home>` — the daemon resolves its
    /// paths exclusively via `crate::paths::DaemonPaths::system()` and
    /// never reads from `$HOME`. The unit MUST declare
    /// `RuntimeDirectory=ember` (resolves to `/run/ember/`),
    /// `StateDirectory=ember` (`/var/lib/ember/`), and
    /// `ConfigurationDirectory=ember` (`/etc/ember/`) so systemd creates
    /// and teardown the daemon's per-OS system paths with the unit's
    /// User/Group. The group switches from `ember` to `ember-clients` so
    /// the kernel-enforced socket ACL on `/run/ember/daemon.sock` is the
    /// per-ADR-131 group. `EMBER_APP_PEM_PATH` / `EMBER_APP_ENV_PATH`
    /// remain (`/etc/emberlink/` is not moved by ADR 218).
    #[test]
    fn systemd_unit_body_matches_adr_218() {
        let expected = [
            "[Unit]",
            "Description=Emberlink Grant Warden daemon",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            "User=ember",
            "Group=ember-clients",
            "Environment=EMBER_APP_PEM_PATH=/etc/emberlink/ember-engine-app.pem",
            "Environment=EMBER_APP_ENV_PATH=/etc/emberlink/ember-engine.env",
            "ExecStart=/usr/local/bin/emberd --foreground",
            "Restart=on-failure",
            "RestartSec=5",
            "",
            "# ADR 218 system-paths — systemd manages /run/ember, /var/lib/ember,",
            "# /etc/ember with the unit's User/Group at the modes below.",
            "RuntimeDirectory=ember",
            "RuntimeDirectoryMode=0750",
            "StateDirectory=ember",
            "StateDirectoryMode=0750",
            "ConfigurationDirectory=ember",
            "",
            // emberd_systemd_seccomp_wired.
            "# emberd_systemd_seccomp_wired — kernel sandbox per META-DAEMON-SECCOMP-PROFILE-HOST.",
            "# Allowlist: systemd-curated baseline + explicit fork/exec/mlock.",
            "SystemCallFilter=@system-service @ipc @memlock",
            "SystemCallFilter=~@raw-io ~@reboot ~@swap ~@cpu-emulation ~@debug ~@mount ~@module ~@obsolete ~@privileged ~@resources",
            "SystemCallErrorNumber=EPERM",
            "SystemCallArchitectures=native",
            "",
            "# Defense-in-depth hardening — systemd primitives complement seccomp.",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectKernelLogs=true",
            "ProtectControlGroups=true",
            "RestrictNamespaces=true",
            "RestrictRealtime=true",
            "RestrictSUIDSGID=true",
            "LockPersonality=true",
            "MemoryDenyWriteExecute=true",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
        .join("\n");
        assert_eq!(
            render_systemd_unit_body(Path::new("/home/test-operator")),
            expected
        );
        // Regression guard: the unit must NOT bake HOME and must NOT
        // re-introduce `Group=ember` (the post-ADR-218 group is
        // `ember-clients` for socket-ACL access).
        let body = render_systemd_unit_body(Path::new("/home/test-operator"));
        assert!(
            !body.contains("Environment=HOME="),
            "systemd unit must NOT bake HOME per ADR 218"
        );
        assert!(
            !body.contains("\nGroup=ember\n"),
            "systemd unit must use Group=ember-clients (not Group=ember) per ADR 131 §Auth model + ADR 218"
        );
    }

    /// The HOME-resolution helper handles the empty-user case cleanly,
    /// regardless of whether it's invoked from a sudo context or not.
    /// We can't reliably test the success path in a unit test (would
    /// need to mock `getpwnam_r`), but the empty-user error path is
    /// the load-bearing safety net — confirm it fires.
    #[test]
    fn resolve_operator_home_refuses_root_only_invocation() {
        // Drop EMBER_OPERATOR + SUDO_USER + force USER=root for this thread;
        // restore on exit. T1 unit — std::env mutation requires a process-wide
        // lock for safety against parallel test threads; gate behind the
        // existing test lock.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior_op = std::env::var("EMBER_OPERATOR").ok();
        let prior_sudo = std::env::var("SUDO_USER").ok();
        let prior_user = std::env::var("USER").ok();
        // SAFETY: std::env::* are unsafe in Rust 2024; we hold PROCESS_TEST_LOCK
        // for the duration so no other thread mutates env concurrently.
        unsafe {
            std::env::remove_var("EMBER_OPERATOR");
            std::env::remove_var("SUDO_USER");
            std::env::set_var("USER", "root");
        }

        let result = resolve_operator_home();

        // Restore environment.
        unsafe {
            match prior_op {
                Some(v) => std::env::set_var("EMBER_OPERATOR", v),
                None => std::env::remove_var("EMBER_OPERATOR"),
            }
            match prior_sudo {
                Some(v) => std::env::set_var("SUDO_USER", v),
                None => std::env::remove_var("SUDO_USER"),
            }
            match prior_user {
                Some(v) => std::env::set_var("USER", v),
                None => std::env::remove_var("USER"),
            }
        }

        assert!(
            result.is_err(),
            "resolve_operator_home must refuse when no operator signal is set, got {:?}",
            result
        );
    }

    /// `EMBER_OPERATOR` is the macOS `.pkg` postinstall's channel for pinning
    /// the operator when the process runs as a pure-root login with no
    /// `$SUDO_USER`. It must win over both `$SUDO_USER` and `$USER` — including
    /// the `USER=root` case the bare-root refusal above guards.
    #[test]
    fn resolve_operator_user_honors_ember_operator_override() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior_op = std::env::var("EMBER_OPERATOR").ok();
        let prior_sudo = std::env::var("SUDO_USER").ok();
        let prior_user = std::env::var("USER").ok();
        // SAFETY: PROCESS_TEST_LOCK held for the duration; no concurrent env mutation.
        unsafe {
            std::env::set_var("EMBER_OPERATOR", "console-operator");
            std::env::set_var("SUDO_USER", "sudo-operator");
            std::env::set_var("USER", "root");
        }

        let resolved = resolve_operator_user();

        unsafe {
            match prior_op {
                Some(v) => std::env::set_var("EMBER_OPERATOR", v),
                None => std::env::remove_var("EMBER_OPERATOR"),
            }
            match prior_sudo {
                Some(v) => std::env::set_var("SUDO_USER", v),
                None => std::env::remove_var("SUDO_USER"),
            }
            match prior_user {
                Some(v) => std::env::set_var("USER", v),
                None => std::env::remove_var("USER"),
            }
        }

        assert_eq!(
            resolved.expect("EMBER_OPERATOR should resolve the operator user"),
            "console-operator",
            "EMBER_OPERATOR must take precedence over SUDO_USER/USER"
        );
    }

    /// Integration-tier — exercises the real macOS launchd install
    /// path. Requires root + a macOS host (mutates
    /// `/Library/LaunchDaemons` and runs `launchctl bootstrap`), so
    /// `#[ignore]` by default. Un-ignore when running the installer
    /// integration suite on a disposable macOS VM.
    #[test]
    #[ignore = "requires root + macOS; mutates /Library/LaunchDaemons and runs launchctl"]
    fn install_launchd_plist_writes_and_bootstraps() {
        let home = resolve_operator_home().expect("operator home");
        install_launchd_plist(&home).expect("first call");
        install_launchd_plist(&home).expect("second call must be a no-op");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn install_launchd_sandbox_profile_into_writes_repo_asset() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let dst = tmp.path().join("sandbox").join("emberd.sb");
        let operator_home = Path::new("/home/test-operator");

        install_launchd_sandbox_profile_into(&dst, operator_home).expect("write sandbox profile");
        install_launchd_sandbox_profile_into(&dst, operator_home)
            .expect("second write must be idempotent");

        let body = std::fs::read_to_string(&dst).expect("read sandbox profile");
        assert_eq!(body, render_launchd_sandbox_profile_body(operator_home));
        // ADR 218: sandbox profile must allowlist the system state root,
        // NOT the retired `~/.ember/` tree.
        let state_root = crate::paths::DaemonPaths::system().state_root;
        let escaped = regex::escape(&state_root.to_string_lossy());
        assert!(
            body.contains(&format!("^{escaped}(/|$)")),
            "sandbox profile must allow writes to the system state root {} per ADR 218",
            state_root.display()
        );
        assert!(
            !body.contains(EMBERD_SANDBOX_WRITE_ALLOWLIST_TOKEN),
            "installed sandbox profile must not leave the template token behind"
        );

        let meta = std::fs::metadata(&dst).expect("sandbox profile metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o644,
            "sandbox profile must be world-readable for launchd/sandbox-exec"
        );
    }

    /// ADR 218 (operator-locked 2026-06-14): sandbox profile must allow
    /// writes to the system state root, NOT the operator-home `~/.ember/`
    /// tree (which is retired). Test rewritten to lock the new boundary.
    #[cfg(target_os = "macos")]
    #[test]
    fn render_launchd_sandbox_profile_body_targets_system_state_root_per_adr_218() {
        let body = render_launchd_sandbox_profile_body(Path::new("/home/test-operator"));
        let state_root = crate::paths::DaemonPaths::system().state_root;
        let state_root_str = state_root.to_string_lossy();
        let escaped = regex::escape(&state_root_str);
        let expected_regex = format!("^{escaped}(/|$)");
        assert!(
            body.contains(&expected_regex),
            "sandbox profile must allow writes under {state_root_str} per ADR 218; body:\n{body}"
        );
        assert!(
            !body.contains(r#"\.ember(/|$)"#),
            "sandbox profile must NOT allowlist the retired ~/.ember/ tree"
        );
        assert!(
            body.contains(r#"^/var/log/emberd(/|$)"#),
            "sandbox profile must keep the launchd log path allowlist"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_service_has_active_process_true_when_active_count_positive() {
        let print_output = "\
system/sh.emberlink.daemon = {\n\
\tactive count = 1\n\
\tstate = running\n\
\texecs = 1\n\
}\n";

        assert!(
            launchd_service_has_active_process(print_output),
            "launchd print output with active count > 0 and real execs must be treated as live"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_service_has_active_process_false_when_active_count_zero() {
        let print_output = "\
system/sh.emberlink.daemon = {\n\
\tactive count = 0\n\
\tstate = spawn scheduled\n\
\tlast exit code = 78: EX_CONFIG\n\
}\n";

        assert!(
            !launchd_service_has_active_process(print_output),
            "launchd print output with active count = 0 must force reinstall bootstrap"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_service_has_active_process_false_when_stuck_in_xpcproxy() {
        let print_output = "\
system/sh.emberlink.daemon = {\n\
\tactive count = 1\n\
\tstate = xpcproxy\n\
\texecs = 0\n\
\tlast exit code = (never exited)\n\
}\n";

        assert!(
            !launchd_service_has_active_process(print_output),
            "launchd xpcproxy placeholder without daemon exec must force reinstall bootstrap"
        );
    }

    /// Integration-tier — exercises the real Linux systemd install
    /// path. Requires root + a Linux host with systemd (mutates
    /// `/etc/systemd/system` and runs `systemctl enable --now`), so
    /// `#[ignore]` by default. Un-ignore when running the installer
    /// integration suite on a disposable Linux VM.
    #[test]
    #[ignore = "requires root + Linux/systemd; mutates /etc/systemd/system and runs systemctl"]
    fn install_systemd_unit_writes_and_enables() {
        let home = resolve_operator_home().expect("operator home");
        install_systemd_unit(&home).expect("first call");
        install_systemd_unit(&home).expect("second call must be a no-op");
    }

    // ── T2: install_pem_to_etc — testable variant ──────────────────────────
    //
    // The real `install_pem_to_etc` shells out `chown root:ember` which
    // requires root. For local CI we test a thin wrapper that accepts an
    // arbitrary destination dir (tmpdir) instead of the hard-coded
    // `/etc/emberlink`. This exercises the copy + chmod logic without
    // needing elevated privileges or touching system state.

    /// Testable version of install_pem_to_etc — same logic but with a
    /// caller-supplied destination directory instead of `/etc/emberlink`.
    /// Allows assertions on mode bits and file presence without root.
    fn install_pem_to_etc_into(operator_home: &Path, dest_dir: &Path) -> Result<(), InstallError> {
        std::fs::create_dir_all(dest_dir)?;

        // Set mode 0750 on the destination dir.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dest_dir, std::fs::Permissions::from_mode(0o750))?;

        let src_config = operator_home.join(".config").join("emberlink");

        for (src_name, dst_name) in &[
            ("ember-engine-app.pem", "ember-engine-app.pem"),
            ("ember-engine.env", "ember-engine.env"),
        ] {
            let src = src_config.join(src_name);
            if !src.exists() {
                continue;
            }

            let dst = dest_dir.join(dst_name);

            copy_root_credential_file_atomic(&src, &dst)?;
        }

        Ok(())
    }

    /// T2 — happy path: source PEM exists, destination is created with
    /// mode 0750, file is written with mode 0440.
    #[test]
    fn install_pem_to_etc_provisions_dir_and_copies_pem() {
        use std::os::unix::fs::PermissionsExt;

        let operator_tmp = tempfile::tempdir().expect("operator tmpdir");
        let dest_tmp = tempfile::tempdir().expect("dest tmpdir");

        // Create source PEM at the expected path.
        let src_config = operator_tmp.path().join(".config").join("emberlink");
        std::fs::create_dir_all(&src_config).expect("create src config dir");
        let pem_src = src_config.join("ember-engine-app.pem");
        std::fs::write(&pem_src, b"--- FAKE PEM ---").expect("write pem src");
        let env_src = src_config.join("ember-engine.env");
        std::fs::write(&env_src, b"EMBER_ENGINE_APP_ID=42").expect("write env src");

        // Run the install into a tmpdir (no root needed).
        let dest_dir = dest_tmp.path().join("etc-emberlink");
        install_pem_to_etc_into(operator_tmp.path(), &dest_dir)
            .expect("install_pem_to_etc_into must succeed");

        // Destination dir must exist with mode 0750.
        let dir_meta = std::fs::metadata(&dest_dir).expect("dest dir metadata");
        assert_eq!(
            dir_meta.permissions().mode() & 0o777,
            0o750,
            "dest dir must have mode 0750"
        );

        // PEM file must exist with mode 0440.
        let pem_dst = dest_dir.join("ember-engine-app.pem");
        assert!(pem_dst.exists(), "ember-engine-app.pem must be copied");
        let pem_meta = std::fs::metadata(&pem_dst).expect("pem metadata");
        assert_eq!(
            pem_meta.permissions().mode() & 0o777,
            0o440,
            "PEM file must have mode 0440"
        );

        // env file must exist with mode 0440.
        let env_dst = dest_dir.join("ember-engine.env");
        assert!(env_dst.exists(), "ember-engine.env must be copied");
        let env_meta = std::fs::metadata(&env_dst).expect("env metadata");
        assert_eq!(
            env_meta.permissions().mode() & 0o777,
            0o440,
            "env file must have mode 0440"
        );
    }

    /// T2 — idempotency: running install twice re-applies mode bits
    /// correctly (no error on second run; modes converge).
    #[test]
    fn install_pem_to_etc_idempotent_on_second_call() {
        use std::os::unix::fs::PermissionsExt;

        let operator_tmp = tempfile::tempdir().expect("operator tmpdir");
        let dest_tmp = tempfile::tempdir().expect("dest tmpdir");

        let src_config = operator_tmp.path().join(".config").join("emberlink");
        std::fs::create_dir_all(&src_config).expect("create src config dir");
        std::fs::write(src_config.join("ember-engine-app.pem"), b"PEM v1").expect("write pem");
        std::fs::write(src_config.join("ember-engine.env"), b"ENV=1").expect("write env");

        let dest_dir = dest_tmp.path().join("etc-emberlink");

        install_pem_to_etc_into(operator_tmp.path(), &dest_dir).expect("first call");

        // Simulate operator chmod drift — relax the PEM to 0644.
        let pem_dst = dest_dir.join("ember-engine-app.pem");
        std::fs::set_permissions(&pem_dst, std::fs::Permissions::from_mode(0o644))
            .expect("relax pem perms");

        // Second call must succeed and converge mode back to 0440.
        install_pem_to_etc_into(operator_tmp.path(), &dest_dir)
            .expect("second call must be a no-op / idempotent");

        let pem_meta = std::fs::metadata(&pem_dst).expect("pem metadata after second call");
        assert_eq!(
            pem_meta.permissions().mode() & 0o777,
            0o440,
            "second call must restore mode 0440 on PEM"
        );
    }

    /// T2 — missing source PEM: when neither source file exists,
    /// install_pem_to_etc returns Ok(()) without erroring (graceful skip).
    #[test]
    fn install_pem_to_etc_graceful_when_source_missing() {
        let operator_tmp = tempfile::tempdir().expect("operator tmpdir");
        let dest_tmp = tempfile::tempdir().expect("dest tmpdir");

        // No source files created — operator hasn't configured GH App yet.
        let dest_dir = dest_tmp.path().join("etc-emberlink");
        let result = install_pem_to_etc_into(operator_tmp.path(), &dest_dir);

        assert!(
            result.is_ok(),
            "missing source PEM must be a graceful skip, got {:?}",
            result
        );

        // Destination dir was created (step 1 always runs).
        assert!(
            dest_dir.exists(),
            "dest dir must be created even when source is missing"
        );

        // No PEM/env file written.
        assert!(
            !dest_dir.join("ember-engine-app.pem").exists(),
            "PEM file must not be created when source is missing"
        );
        assert!(
            !dest_dir.join("ember-engine.env").exists(),
            "env file must not be created when source is missing"
        );
    }

    /// T2 — the plist body includes EMBER_APP_PEM_PATH pointing at
    /// `/etc/emberlink/ember-engine-app.pem`.
    #[test]
    fn plist_body_contains_ember_app_pem_path() {
        let body = render_launchd_plist_body(Path::new("/home/test-operator"));
        assert!(
            body.contains("EMBER_APP_PEM_PATH"),
            "plist must contain EMBER_APP_PEM_PATH key"
        );
        assert!(
            body.contains("/etc/emberlink/ember-engine-app.pem"),
            "plist must reference /etc/emberlink/ember-engine-app.pem"
        );
        assert!(
            body.contains("EMBER_APP_ENV_PATH"),
            "plist must contain EMBER_APP_ENV_PATH key"
        );
        assert!(
            body.contains("/etc/emberlink/ember-engine.env"),
            "plist must reference /etc/emberlink/ember-engine.env"
        );
    }

    /// T2 — the systemd unit includes Environment= lines for
    /// EMBER_APP_PEM_PATH and EMBER_APP_ENV_PATH.
    #[test]
    fn systemd_unit_body_contains_ember_app_paths() {
        let body = render_systemd_unit_body(Path::new("/home/test-operator"));
        assert!(
            body.contains("Environment=EMBER_APP_PEM_PATH=/etc/emberlink/ember-engine-app.pem"),
            "systemd unit must contain Environment=EMBER_APP_PEM_PATH line"
        );
        assert!(
            body.contains("Environment=EMBER_APP_ENV_PATH=/etc/emberlink/ember-engine.env"),
            "systemd unit must contain Environment=EMBER_APP_ENV_PATH line"
        );
    }

    // emberd_systemd_seccomp_wired tests.

    #[test]
    fn systemd_unit_body_contains_seccomp_filter() {
        let body = render_systemd_unit_body(Path::new("/home/test-operator"));
        assert!(
            body.contains("SystemCallFilter=@system-service"),
            "systemd unit must wire @system-service syscall allowlist"
        );
        assert!(
            body.contains("SystemCallErrorNumber=EPERM"),
            "systemd unit must set EPERM as the seccomp error return"
        );
        assert!(
            body.contains("~@privileged"),
            "systemd unit must explicitly deny @privileged syscall set"
        );
    }

    #[test]
    fn systemd_unit_body_contains_defense_in_depth_hardening() {
        let body = render_systemd_unit_body(Path::new("/home/test-operator"));
        // Spot-check a few key hardening directives. Full enumeration
        // would over-specify and fight legitimate iteration on the
        // systemd profile; these are the load-bearing few that pair
        // with the seccomp filter to deny common privilege-escalation
        // paths even if a syscall slips through.
        for directive in [
            "NoNewPrivileges=true",
            "ProtectKernelModules=true",
            "RestrictSUIDSGID=true",
            "MemoryDenyWriteExecute=true",
        ] {
            assert!(
                body.contains(directive),
                "systemd unit must contain hardening directive `{directive}`"
            );
        }
    }

    #[test]
    fn systemd_unit_body_contains_seccomp_sentinel() {
        let body = render_systemd_unit_body(Path::new("/home/test-operator"));
        assert!(
            body.contains("emberd_systemd_seccomp_wired"),
            "systemd unit must carry the checkpoint comment for grep-based detection"
        );
    }

    // ── resolve_emberd_source + install_emberd_binary_at ────

    /// Serialize tests that mutate process env. `EMBER_EMBERD_BIN_PATH`
    /// is process-global; two override tests racing under cargo's
    /// parallel runner would flake otherwise.
    static EMBERD_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Drop-restore guard for `EMBER_EMBERD_BIN_PATH`. Failing tests
    /// still restore the original value so subsequent tests aren't
    /// poisoned by leaked env state.
    struct EmberdEnvGuard {
        previous: Option<String>,
    }
    impl EmberdEnvGuard {
        fn set(value: &str) -> Self {
            let previous = std::env::var(ENV_EMBERD_BIN_PATH).ok();
            unsafe { std::env::set_var(ENV_EMBERD_BIN_PATH, value) };
            Self { previous }
        }
        // Symmetric `unset` constructor to `set`. No caller in src/
        // today; preserve the test-helper API surface so future tests
        // that need the "ensure ENV is absent before this scope" shape
        // can use it without re-inventing the Drop-restore guard.
        #[allow(dead_code)]
        fn unset() -> Self {
            let previous = std::env::var(ENV_EMBERD_BIN_PATH).ok();
            unsafe { std::env::remove_var(ENV_EMBERD_BIN_PATH) };
            Self { previous }
        }
    }
    impl Drop for EmberdEnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(v) => std::env::set_var(ENV_EMBERD_BIN_PATH, v),
                    None => std::env::remove_var(ENV_EMBERD_BIN_PATH),
                }
            }
        }
    }

    /// T1 — env-var override is authoritative when set to an existing path.
    #[test]
    fn resolve_emberd_source_honors_env_override() {
        let _lock = EMBERD_ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("custom-emberd");
        std::fs::write(&src, b"#!/bin/sh\nexit 0\n").expect("write fake binary");
        let _g = EmberdEnvGuard::set(src.to_str().expect("utf-8 path"));

        let resolved = resolve_emberd_source().expect("override path must resolve");
        assert_eq!(resolved, src);
    }

    /// T1 — empty env var is treated as unset (falls through to sibling
    /// lookup). Defense against accidental `Environment=EMBER_EMBERD_BIN_PATH=`.
    #[test]
    fn resolve_emberd_source_empty_env_treated_as_unset() {
        let _lock = EMBERD_ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EmberdEnvGuard::set("");
        // Sibling lookup may succeed or fail depending on whether the
        // test runner happens to have an `emberd` sibling — we only
        // assert that the empty-env-var branch did NOT short-circuit
        // into the override path. A successful resolution means the
        // fall-through reached sibling lookup; a sibling-not-found
        // error proves the same. Either way: NOT an override-path-empty
        // error.
        match resolve_emberd_source() {
            Ok(_) => {} // sibling found
            Err(InstallError::Subprocess { stderr, .. }) => {
                assert!(
                    !stderr.contains("does not exist") || !stderr.contains("\"\""),
                    "empty env var leaked into override path: {stderr}"
                );
                assert!(
                    stderr.contains("could not find `emberd`") || stderr.contains("current_exe"),
                    "empty env var should fall through to sibling lookup, got: {stderr}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// T1 — insiders/release macOS host installs place `ember` and `emberd`
    /// in separate signed app bundles. `sudo ember daemon install` runs from
    /// `/usr/local/lib/ember.app/.../ember`, so there is intentionally no
    /// same-directory `emberd` sibling; the managed daemon path is the source
    /// to publish/no-op against.
    #[test]
    fn resolve_emberd_source_installed_app_uses_managed_daemon_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let current = tmp
            .path()
            .join("usr/local/lib/ember.app/Contents/MacOS/ember");
        std::fs::create_dir_all(current.parent().expect("current parent")).expect("mkdir app");
        std::fs::write(&current, b"fake-ember").expect("write fake ember");

        let managed = tmp.path().join("usr/local/bin/emberd");
        std::fs::create_dir_all(managed.parent().expect("managed parent")).expect("mkdir bin");
        std::fs::write(&managed, b"fake-emberd").expect("write fake emberd");

        let resolved = resolve_emberd_source_from_current_exe(&current, &managed)
            .expect("installed app layout must resolve managed emberd");
        assert_eq!(resolved, managed);
    }

    /// T1 — the managed-daemon fallback is only for the installed app-bundle
    /// launcher. A repo-build `target/.../ember` without an `emberd` sibling
    /// must not silently reuse an unrelated host daemon.
    #[test]
    fn resolve_emberd_source_repo_build_without_sibling_rejects_managed_daemon_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let current = tmp.path().join("target/release/ember");
        std::fs::create_dir_all(current.parent().expect("current parent")).expect("mkdir target");
        std::fs::write(&current, b"fake-ember").expect("write fake ember");

        let managed = tmp.path().join("usr/local/bin/emberd");
        std::fs::create_dir_all(managed.parent().expect("managed parent")).expect("mkdir bin");
        std::fs::write(&managed, b"fake-emberd").expect("write fake emberd");

        let err = match resolve_emberd_source_from_current_exe(&current, &managed) {
            Err(e) => e,
            Ok(path) => panic!("repo build must not resolve managed daemon path: {path:?}"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("could not find `emberd` next to"),
            "error should preserve sibling-build guidance: {msg}"
        );
    }

    /// T1 — `..` segment in env var is refused with a named error.
    #[test]
    fn resolve_emberd_source_rejects_parent_dir_traversal() {
        let _lock = EMBERD_ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EmberdEnvGuard::set("/usr/local/bin/../../etc/passwd");
        let err = match resolve_emberd_source() {
            Err(e) => e,
            Ok(_) => panic!("must refuse `..` segments"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains(ENV_EMBERD_BIN_PATH),
            "error must name the offending env var: {msg}"
        );
        assert!(
            msg.contains(".."),
            "error must mention the `..` segment: {msg}"
        );
    }

    /// T1 — env-var override to a non-existent path errors with a clear msg.
    #[test]
    fn resolve_emberd_source_env_path_must_exist() {
        let _lock = EMBERD_ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let _g = EmberdEnvGuard::set("/nonexistent/path/to/emberd-12345");
        let err = match resolve_emberd_source() {
            Err(e) => e,
            Ok(_) => panic!("must error when override path is missing"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("does not exist"),
            "error must explain the path is missing: {msg}"
        );
    }

    /// T1 — copy + chmod cycle into a tempdir destination. Verifies the
    /// happy path of `install_emberd_binary_at`. Skips the chown step
    /// asserts (the test process isn't root) — we just verify the file
    /// arrives at the destination with the source contents.
    #[test]
    fn install_emberd_binary_at_copies_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("source-emberd");
        let dst_dir = tmp.path().join("dst");
        std::fs::write(&src, b"fake-binary-contents").expect("write source");

        // chown will fail (we're not root) — but the function still
        // performs the copy + chmod before chown. We catch the chown
        // failure here and verify the copy step succeeded.
        let result = install_emberd_binary_at(&src, &dst_dir, "emberd");
        let installed = dst_dir.join("emberd");
        assert!(
            installed.exists(),
            "binary must be copied to destination even if a later step fails"
        );
        let body = std::fs::read(&installed).expect("read installed");
        assert_eq!(body, b"fake-binary-contents");
        // The chown to root:wheel/root:root will fail under a non-root
        // test runner; surface the error type but don't fail the test.
        match result {
            Ok(()) => {}
            Err(InstallError::Subprocess { cmd, .. }) if cmd.starts_with("chown ") => {}
            Err(other) => panic!(
                "unexpected error variant (only `chown` failure is expected under non-root tests): {other:?}"
            ),
        }
    }

    /// T1 — idempotent re-copy. Running install over an existing
    /// destination unlinks the old inode and writes a fresh one. The
    /// new file picks up new contents from the source.
    #[test]
    fn install_emberd_binary_at_idempotent_with_replacement() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("source-emberd");
        let dst_dir = tmp.path().join("dst");
        std::fs::create_dir(&dst_dir).expect("mkdir dst");
        let dst = dst_dir.join("emberd");

        // Existing dst with stale contents.
        std::fs::write(&dst, b"OLD-binary").expect("write old dst");
        // New source contents.
        std::fs::write(&src, b"NEW-binary").expect("write new source");

        // Tolerate chown failure under non-root.
        let _ = install_emberd_binary_at(&src, &dst_dir, "emberd");

        let body = std::fs::read(&dst).expect("read dst after install");
        assert_eq!(body, b"NEW-binary", "stale dst must be replaced");
    }

    // ── T2: bootout_tolerant — mock-runner unit tests ──────────────────────
    //
    // These tests exercise `bootout_tolerant_inner` directly, injecting
    // canned (exit_code, stderr, success) tuples instead of spawning a
    // real `launchctl` subprocess. All three tests are macOS-only because
    // `bootout_tolerant_inner` is `#[cfg(target_os = "macos")]`.

    /// T2 — macOS 26+ EIO surface is tolerated.
    /// `launchctl bootout` on a service that isn't loaded returns exit 5
    /// with stderr "Boot-out failed: 5: Input/output error" on macOS 26+.
    /// The installer must not surface this as a failure.
    #[test]
    #[cfg(target_os = "macos")]
    fn bootout_tolerant_accepts_macos_26_eio_surface() {
        let result = bootout_tolerant_inner("launchctl bootout system <plist>", || {
            Ok((
                Some(5),
                "Boot-out failed: 5: Input/output error".to_string(),
                false,
            ))
        });
        assert!(
            result.is_ok(),
            "exit 5 + 'Boot-out failed: 5: Input/output error' must be tolerated (macOS 26+ surface for service-not-loaded), got: {result:?}"
        );
    }

    /// T2 — pre-macOS 26 "not found" surface is still tolerated (regression
    /// guard). Exit 113 + "Could not find specified service" is the legacy
    /// shape emitted when bootout is called for a service that isn't loaded.
    #[test]
    #[cfg(target_os = "macos")]
    fn bootout_tolerant_accepts_legacy_exit_113_not_found() {
        let result = bootout_tolerant_inner("launchctl bootout system <plist>", || {
            Ok((
                Some(113),
                "Could not find specified service".to_string(),
                false,
            ))
        });
        assert!(
            result.is_ok(),
            "exit 113 + 'Could not find specified service' must be tolerated (legacy macOS surface), got: {result:?}"
        );
    }

    /// T2 — unrelated EIO (exit 5 with a different stderr prefix) is NOT
    /// swallowed. Only the exact "Boot-out failed: 5: Input/output error"
    /// prefix is tolerated; other exit-5 failures from launchd are real
    /// errors and must propagate.
    #[test]
    #[cfg(target_os = "macos")]
    fn bootout_tolerant_rejects_unrelated_eio() {
        let result = bootout_tolerant_inner("launchctl bootout system <plist>", || {
            Ok((
                Some(5),
                "Some other I/O error from launchd".to_string(),
                false,
            ))
        });
        assert!(
            result.is_err(),
            "exit 5 with a different stderr prefix must NOT be swallowed, got: {result:?}"
        );
    }

    // ── T1: ensure_emberd_log_paths — mock-based unit tests ───────────────
    //
    // Uses `ensure_emberd_log_paths_inner` directly so no real `ember`
    // system user or root privileges are required. Log file paths are
    // redirected into a tempdir so the test doesn't touch `/var/log`.

    /// T1 — happy path: both log files are created with mode 0644 and the
    /// chown closure is called for each path with the mocked uid/gid.
    #[test]
    #[cfg(target_os = "macos")]
    fn ensure_emberd_log_paths_creates_files_with_ember_ownership() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let err_path = tmp.path().join("emberd.err");
        let out_path = tmp.path().join("emberd.out");

        // Mock ember user: uid=500, gid=500 (representative non-root values).
        let mock_uid: libc::uid_t = 500;
        let mock_gid: libc::gid_t = 500;

        let mut chowned: Vec<(std::path::PathBuf, libc::uid_t, libc::gid_t)> = Vec::new();

        let result = ensure_emberd_log_paths_inner(
            &err_path,
            &out_path,
            || Some((mock_uid, mock_gid)),
            |path, uid, gid| {
                chowned.push((path.to_path_buf(), uid, gid));
                Ok(())
            },
        );

        assert_eq!(
            result.expect("ensure_emberd_log_paths_inner must succeed with mocked ember user"),
            true,
            "fresh log-path install must report that it repaired host state"
        );

        // Both files must exist.
        assert!(err_path.exists(), "emberd.err must be created");
        assert!(out_path.exists(), "emberd.out must be created");

        // Both files must have mode 0644.
        let err_meta = std::fs::metadata(&err_path).expect("err metadata");
        assert_eq!(
            err_meta.permissions().mode() & 0o777,
            0o644,
            "emberd.err must have mode 0644"
        );
        let out_meta = std::fs::metadata(&out_path).expect("out metadata");
        assert_eq!(
            out_meta.permissions().mode() & 0o777,
            0o644,
            "emberd.out must have mode 0644"
        );

        // chown closure must have been called for each file with the mocked uid/gid.
        assert_eq!(chowned.len(), 2, "chown must be called for both log files");
        for (path, uid, gid) in &chowned {
            assert_eq!(
                *uid,
                mock_uid,
                "uid must match mocked ember uid for {}",
                path.display()
            );
            assert_eq!(
                *gid,
                mock_gid,
                "gid must match mocked ember gid for {}",
                path.display()
            );
        }
        let chowned_paths: Vec<&std::path::Path> =
            chowned.iter().map(|(p, _, _)| p.as_path()).collect();
        assert!(
            chowned_paths.contains(&err_path.as_path()),
            "chown must be called for emberd.err"
        );
        assert!(
            chowned_paths.contains(&out_path.as_path()),
            "chown must be called for emberd.out"
        );
    }

    /// T1 — absent ember user: when lookup returns None, the function fails
    /// with a clear error pointing at provision_ember_user.
    #[test]
    #[cfg(target_os = "macos")]
    fn ensure_emberd_log_paths_fails_clearly_if_ember_user_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err_path = tmp.path().join("emberd.err");
        let out_path = tmp.path().join("emberd.out");

        let result = ensure_emberd_log_paths_inner(
            &err_path,
            &out_path,
            || None,                    // ember user does not exist
            |_path, _uid, _gid| Ok(()), // chown should never be called
        );

        assert!(
            result.is_err(),
            "must fail when ember user is absent, got: {result:?}"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("provision_ember_user"),
            "error must point at provision_ember_user, got: {err_msg}"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn ensure_emberd_log_paths_false_when_files_already_match() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = tempfile::tempdir().expect("tempdir");
        let err_path = tmp.path().join("emberd.err");
        let out_path = tmp.path().join("emberd.out");

        std::fs::write(&err_path, b"existing stderr").expect("seed err log");
        std::fs::write(&out_path, b"existing stdout").expect("seed out log");
        std::fs::set_permissions(&err_path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod err");
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod out");

        let err_meta = std::fs::metadata(&err_path).expect("err metadata");
        let mock_uid = err_meta.uid();
        let mock_gid = err_meta.gid();

        let changed = ensure_emberd_log_paths_inner(
            &err_path,
            &out_path,
            || Some((mock_uid, mock_gid)),
            |_path, _uid, _gid| Ok(()),
        )
        .expect("matching log files must succeed");

        assert!(
            !changed,
            "already-correct log paths must not force a launchd restart"
        );
    }

    // ── subuid install tests ───────────────────────
    //
    // ADR 155 Component 2 modern-Linux subuid install path. Tests use
    // `provision_subuid_range_at` against tempdir-scoped `subuid` /
    // `subgid` files so no root or `/etc/` mutation is required.

    /// T2 — fresh install: empty (nonexistent) subuid/subgid files
    /// get an `ember:100000:8192` line appended. Returns the
    /// `Subuid` provisioning variant with matching values.
    #[test]
    fn provision_subuid_range_writes_to_fresh_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let subuid = tmp.path().join("subuid");
        let subgid = tmp.path().join("subgid");

        // Don't pre-create — provision_subuid_range_at must tolerate
        // missing files (treated as empty content).
        let result = provision_subuid_range_at(&subuid, &subgid, 100_000, 8192);
        let prov = result.expect("fresh install must succeed");

        // Verify return value matches.
        match prov {
            SpawnPoolProvisioning::Subuid {
                range_start,
                slot_count,
            } => {
                assert_eq!(range_start, 100_000);
                assert_eq!(slot_count, 8192);
            }
            other => panic!("expected Subuid variant, got: {other:?}"),
        }

        // Verify the file contents.
        let subuid_contents =
            std::fs::read_to_string(&subuid).expect("subuid file must be written");
        assert!(
            subuid_contents.contains("ember:100000:8192"),
            "subuid must contain ember:100000:8192, got: {subuid_contents:?}"
        );
        let subgid_contents =
            std::fs::read_to_string(&subgid).expect("subgid file must be written");
        assert!(
            subgid_contents.contains("ember:100000:8192"),
            "subgid must contain ember:100000:8192, got: {subgid_contents:?}"
        );
    }

    /// T2 — idempotency: running provision twice produces the same
    /// file contents. The second call detects the existing matching
    /// entry and returns Ok without re-writing.
    #[test]
    fn provision_subuid_range_idempotent_on_second_call() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let subuid = tmp.path().join("subuid");
        let subgid = tmp.path().join("subgid");

        provision_subuid_range_at(&subuid, &subgid, 100_000, 8192).expect("first call");
        let first_subuid = std::fs::read_to_string(&subuid).expect("read after first");
        let first_subgid = std::fs::read_to_string(&subgid).expect("read after first");

        provision_subuid_range_at(&subuid, &subgid, 100_000, 8192)
            .expect("second call must be a no-op");
        let second_subuid = std::fs::read_to_string(&subuid).expect("read after second");
        let second_subgid = std::fs::read_to_string(&subgid).expect("read after second");

        assert_eq!(
            first_subuid, second_subuid,
            "second call must not modify subuid (got drift: {first_subuid:?} -> {second_subuid:?})"
        );
        assert_eq!(
            first_subgid, second_subgid,
            "second call must not modify subgid (got drift: {first_subgid:?} -> {second_subgid:?})"
        );

        // Exactly one ember: entry — no duplicates from re-append.
        let ember_lines: Vec<&str> = second_subuid
            .lines()
            .filter(|l| l.trim_start().starts_with("ember:"))
            .collect();
        assert_eq!(
            ember_lines.len(),
            1,
            "must have exactly one ember: entry, got: {ember_lines:?}"
        );
    }

    /// T2 — range collision: an existing `ember:OTHER:OTHER` entry
    /// causes provision to refuse rather than silently overwrite.
    /// The error message names both the existing and desired ranges
    /// so the operator can resolve manually.
    #[test]
    fn provision_subuid_range_refuses_conflicting_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let subuid = tmp.path().join("subuid");
        let subgid = tmp.path().join("subgid");

        // Pre-populate with a conflicting entry (different range).
        std::fs::write(&subuid, b"ember:200000:65536\n").expect("write conflicting subuid");
        std::fs::write(&subgid, b"ember:200000:65536\n").expect("write conflicting subgid");

        let result = provision_subuid_range_at(&subuid, &subgid, 100_000, 8192);
        let err = match result {
            Err(e) => e,
            Ok(prov) => panic!("must refuse conflicting entry; got Ok({prov:?})"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("200000"),
            "error must name the existing range: {msg}"
        );
        assert!(
            msg.contains("100000"),
            "error must name the desired range: {msg}"
        );
        assert!(
            msg.contains("ember:"),
            "error must reference the ember subuid entry: {msg}"
        );

        // Files must be unchanged on conflict — we refused to write.
        let subuid_after = std::fs::read_to_string(&subuid).expect("read subuid after refusal");
        assert_eq!(
            subuid_after, "ember:200000:65536\n",
            "subuid must be unchanged on conflict; got: {subuid_after:?}"
        );
    }

    /// T2 — preserves unrelated entries: provision appends to a
    /// file that already has entries for other users (typical
    /// real-world `/etc/subuid` content). Idempotency check
    /// against the line count after both calls.
    #[test]
    fn provision_subuid_range_preserves_unrelated_entries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let subuid = tmp.path().join("subuid");
        let subgid = tmp.path().join("subgid");

        // Pre-populate with realistic content from a typical Linux
        // host (dockerd subuid, regular user subuid).
        let pre_existing = "docker:165536:65536\nalice:100000:65536\n";
        std::fs::write(&subuid, pre_existing).expect("write pre-existing");
        std::fs::write(&subgid, pre_existing).expect("write pre-existing");

        provision_subuid_range_at(&subuid, &subgid, 500_000, 8192).expect("provision must succeed");

        let after = std::fs::read_to_string(&subuid).expect("read after");
        assert!(
            after.contains("docker:165536:65536"),
            "docker entry must be preserved, got: {after:?}"
        );
        assert!(
            after.contains("alice:100000:65536"),
            "alice entry must be preserved, got: {after:?}"
        );
        assert!(
            after.contains("ember:500000:8192"),
            "ember entry must be appended, got: {after:?}"
        );
    }

    /// T2 — find_ember_subuid_entry: matching shape returns Match.
    #[test]
    fn find_ember_subuid_entry_matches_exact() {
        let contents = "docker:165536:65536\nember:100000:8192\nalice:200000:65536\n";
        let found = find_ember_subuid_entry(contents, 100_000, 8192);
        assert_eq!(found, Some(EmberSubuidEntry::Match));
    }

    /// T2 — find_ember_subuid_entry: different range returns Conflict.
    #[test]
    fn find_ember_subuid_entry_detects_conflict() {
        let contents = "ember:200000:16384\n";
        let found = find_ember_subuid_entry(contents, 100_000, 8192);
        assert_eq!(
            found,
            Some(EmberSubuidEntry::Conflict {
                existing_start: 200_000,
                existing_count: 16_384,
            })
        );
    }

    /// T2 — find_ember_subuid_entry: no ember line returns None.
    #[test]
    fn find_ember_subuid_entry_returns_none_when_absent() {
        let contents = "docker:165536:65536\nalice:200000:65536\n";
        let found = find_ember_subuid_entry(contents, 100_000, 8192);
        assert_eq!(found, None);
    }

    /// T2 — find_ember_subuid_entry: empty content returns None.
    #[test]
    fn find_ember_subuid_entry_handles_empty() {
        assert_eq!(find_ember_subuid_entry("", 100_000, 8192), None);
    }

    /// T2 — find_ember_subuid_entry: skips comment lines and blank lines.
    #[test]
    fn find_ember_subuid_entry_skips_comments_and_blanks() {
        let contents = "# header comment\n\n# another comment\nember:100000:8192\n";
        let found = find_ember_subuid_entry(contents, 100_000, 8192);
        assert_eq!(found, Some(EmberSubuidEntry::Match));
    }

    /// T2 — find_ember_subuid_entry: garbage lines (wrong column
    /// count, non-numeric) are skipped silently.
    #[test]
    fn find_ember_subuid_entry_skips_malformed_lines() {
        let contents = "malformed line\nember:abc:def\nember:100000:8192\n";
        let found = find_ember_subuid_entry(contents, 100_000, 8192);
        assert_eq!(found, Some(EmberSubuidEntry::Match));
    }

    /// T2 — find_ember_subuid_entry: TWO `ember:` lines, both
    /// well-formed, return `MultipleEntries` regardless of whether
    /// the values match. Defense-in-depth against shadow-utils'
    /// "union all matching lines" newuidmap semantics — an attacker
    /// with root who appends a second `ember:0:65536` line would
    /// silently grant uid 0 mapping authority while a single-line
    /// check would see only the first line. The install path
    /// refuses; operator must consolidate.
    #[test]
    fn find_ember_subuid_entry_detects_multiple_entries() {
        let contents = "ember:100000:8192\nember:0:65536\n";
        let found = find_ember_subuid_entry(contents, 100_000, 8192);
        match found {
            Some(EmberSubuidEntry::MultipleEntries { count, lines }) => {
                assert_eq!(count, 2, "expected 2 ember entries, got {count}");
                assert_eq!(
                    lines.len(),
                    2,
                    "lines vec must carry both entries, got: {lines:?}"
                );
                assert!(
                    lines.iter().any(|l| l.contains("100000")),
                    "lines must include the first entry: {lines:?}"
                );
                assert!(
                    lines.iter().any(|l| l.contains(":0:")),
                    "lines must include the hostile second entry: {lines:?}"
                );
            }
            other => panic!("expected MultipleEntries; got {other:?}"),
        }
    }

    /// T2 — find_ember_subuid_entry_multiple_entries_refused (named
    /// per the brief): a file with two ember lines triggers a
    /// refusal at `ensure_subuid_entry`/`provision_subuid_range_at`
    /// boundary, not just at the lower-level parser. End-to-end
    /// regression guard.
    #[test]
    fn find_ember_subuid_entry_multiple_entries_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let subuid = tmp.path().join("subuid");
        let subgid = tmp.path().join("subgid");

        // Pre-populate the subuid file with TWO ember lines — the
        // legit install line + a hostile second line.
        let two_lines = "ember:100000:8192\nember:0:65536\n";
        std::fs::write(&subuid, two_lines).expect("write 2-line subuid");
        std::fs::write(&subgid, two_lines).expect("write 2-line subgid");

        let result = provision_subuid_range_at(&subuid, &subgid, 100_000, 8192);
        let err = match result {
            Err(e) => e,
            Ok(prov) => panic!("provision must refuse 2-line subuid; got Ok({prov:?})"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("2 `ember:`") || msg.contains("2 ember"),
            "error must name the line count: {msg}"
        );
        assert!(
            msg.contains("shadow-utils unions") || msg.contains("union"),
            "error must explain shadow-utils union semantics: {msg}"
        );
        assert!(
            msg.contains("consolidate"),
            "error must surface the actionable remediation: {msg}"
        );

        // Files unchanged on refusal — we must not silently truncate
        // even one of the hostile lines.
        let after = std::fs::read_to_string(&subuid).expect("read after refusal");
        assert_eq!(
            after, two_lines,
            "subuid must be untouched on multi-entry refusal; got: {after:?}"
        );
    }

    /// T2 — verify_newuidmap_binary: missing binary surfaces a
    /// clear refusal with install hints for both Debian/Ubuntu and
    /// RHEL/Fedora package managers.
    #[test]
    fn newuidmap_install_probe_refuses_missing_binary() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Path doesn't exist — verify_newuidmap_binary must refuse.
        let missing = tmp.path().join("does-not-exist-newuidmap");

        let result = verify_newuidmap_binary(&missing);
        let err = result.expect_err("missing binary must surface InstallError");
        let msg = format!("{err}");
        assert!(
            msg.contains("not installed"),
            "error must surface the install hint: {msg}"
        );
        assert!(
            msg.contains("apt install uidmap") || msg.contains("dnf install shadow-utils"),
            "error must name at least one distro install command: {msg}"
        );
    }

    /// T2 — verify_newuidmap_binary: non-setuid file at the path
    /// surfaces a clear refusal pointing at the setuid-root
    /// requirement.
    #[cfg(target_family = "unix")]
    #[test]
    fn newuidmap_install_probe_refuses_non_setuid_binary() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let fake_binary = tmp.path().join("fake-newuidmap");
        // Create a file with mode 0755 (executable but NOT setuid).
        // owner_uid = test process's uid (definitely != 0 in
        // sandboxed CI).
        std::fs::write(&fake_binary, b"#!/bin/sh\nexit 0\n").expect("write fake binary");
        let mut perms = std::fs::metadata(&fake_binary)
            .expect("stat fake binary")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_binary, perms).expect("chmod fake binary");

        let result = verify_newuidmap_binary(&fake_binary);
        let err = result.expect_err("non-setuid binary must surface InstallError");
        let msg = format!("{err}");
        assert!(
            msg.contains("setuid"),
            "error must name the setuid-root requirement: {msg}"
        );
        assert!(
            msg.contains("0o4000") || msg.contains("CAP_SETUID"),
            "error must surface the underlying mechanism (mode or capability): {msg}"
        );
    }

    /// T2 — render_spawn_pool_toml emits the subuid shape for the
    /// Subuid variant. The rendered TOML must be parseable by the
    /// daemon's SpawnPoolConfig deserializer.
    #[test]
    fn render_spawn_pool_toml_emits_subuid_shape() {
        let prov = SpawnPoolProvisioning::Subuid {
            range_start: 100_000,
            slot_count: 8192,
        };
        let rendered = render_spawn_pool_toml(&prov);
        assert!(
            rendered.contains("subuid_range_start = 100000"),
            "rendered TOML must contain subuid_range_start, got: {rendered:?}"
        );
        assert!(
            rendered.contains("subuid_range_slots = 8192"),
            "rendered TOML must contain subuid_range_slots, got: {rendered:?}"
        );
        // No `uids = [...]` line on the Subuid path — the kernel-side
        // subuid range IS the pool.
        assert!(
            !rendered.contains("uids = ["),
            "Subuid render must not emit uids list, got: {rendered:?}"
        );
    }

    /// T2 — render_spawn_pool_toml emits the system-user shape for the
    /// SystemUsers variant. Regression guard against the enum refactor
    /// changing the legacy shape.
    #[test]
    fn render_spawn_pool_toml_emits_system_users_shape() {
        let prov = SpawnPoolProvisioning::SystemUsers {
            uids: vec![10010, 10011, 10012],
            gid: 10020,
        };
        let rendered = render_spawn_pool_toml(&prov);
        assert!(
            rendered.contains("uids = [10010, 10011, 10012]"),
            "rendered TOML must contain uids list, got: {rendered:?}"
        );
        assert!(
            rendered.contains("gid = 10020"),
            "rendered TOML must contain gid, got: {rendered:?}"
        );
    }

    /// T2 — render_spawn_pool_toml emits the same system-user shape
    /// for ManualCommands as for SystemUsers (the rendered config is
    /// the operator's expected end-state once they run the manual
    /// commands; the commands themselves are surfaced separately by
    /// the installer).
    #[test]
    fn render_spawn_pool_toml_manual_commands_emits_system_users_shape() {
        let prov = SpawnPoolProvisioning::ManualCommands {
            uids: vec![10010, 10011],
            gid: 0,
            commands: vec!["sudo dscl . -create /Users/ember-spawn-0".to_string()],
        };
        let rendered = render_spawn_pool_toml(&prov);
        assert!(
            rendered.contains("uids = [10010, 10011]"),
            "ManualCommands render must contain uids list, got: {rendered:?}"
        );
        assert!(
            rendered.contains("gid = 0"),
            "ManualCommands render must contain gid, got: {rendered:?}"
        );
    }

    /// T1 — `write_spawn_pool_config_inner` writes `[spawn_pool]` into a
    /// fresh `config.toml` (system config path per ADR 218) and the
    /// daemon-side TOML deserializer round-trips it. The test drives the
    /// inner variant with `DaemonPaths::for_test(tmp)` so the write
    /// targets `<tmp>/config/config.toml` instead of the real system
    /// path.
    #[test]
    fn write_spawn_pool_config_creates_section() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        let prov = SpawnPoolProvisioning::SystemUsers {
            uids: vec![10010, 10011, 10012],
            gid: 10020,
        };
        write_spawn_pool_config_inner(&paths, &prov).expect("write config");

        let text = std::fs::read_to_string(paths.config_file()).expect("config written");
        assert!(
            text.contains("[spawn_pool]"),
            "section header present: {text}"
        );
        assert!(
            text.contains("uids = [10010, 10011, 10012]"),
            "uids: {text}"
        );
        assert!(text.contains("gid = 10020"), "gid: {text}");
    }

    /// T1 — `write_default_config_if_absent_inner` writes a bootable base
    /// config (`[daemon]` + `[keyring]`) into the daemon's system config
    /// path (per ADR 218 — `DaemonPaths::config_file()`). This is the
    /// fix for the fresh-`.pkg`-install daemon-won't-boot gap (ADR 202
    /// §Decision 2), now retargeted to the system path.
    #[test]
    fn write_default_config_creates_bootable_base() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        write_default_config_if_absent_inner(&paths).expect("write config");

        let text = std::fs::read_to_string(paths.config_file()).expect("config written");
        assert!(text.contains("[daemon]"), "daemon section: {text}");
        assert!(text.contains("log_level = \"info\""), "log level: {text}");
        assert!(text.contains("[keyring]"), "keyring section: {text}");
        // Round-trips through the daemon-side config deserializer.
        let parsed: toml::Value = toml::from_str(&text).expect("config parses as TOML");
        assert!(parsed.get("daemon").is_some(), "daemon table present");
        assert!(parsed.get("keyring").is_some(), "keyring table present");
    }

    /// T1 — non-clobbering: an existing `config.toml` (operator edits, a
    /// prior install's settings, an upgrade-over-existing host) is
    /// authoritative and left byte-for-byte untouched.
    #[test]
    fn write_default_config_does_not_clobber_existing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).expect("mkdir config dir");
        let existing = "[daemon]\nlog_level = \"debug\"\ntrust_roots = \"operator-pinned\"\n";
        std::fs::write(paths.config_file(), existing).expect("seed config");

        write_default_config_if_absent_inner(&paths).expect("idempotent no-op");

        let text = std::fs::read_to_string(paths.config_file()).expect("config still there");
        assert_eq!(text, existing, "existing config must be left untouched");
    }

    #[test]
    #[cfg(unix)]
    fn write_default_config_if_absent_refuses_symlinked_config() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).expect("mkdir config dir");
        let target = tmp.path().join("attacker-target.toml");
        symlink(&target, paths.config_file()).expect("create dangling config symlink");

        let err = write_default_config_if_absent_inner(&paths)
            .expect_err("default config writer must reject symlinked config paths");

        match err {
            InstallError::Subprocess { stderr, .. } => assert!(
                stderr.contains("refusing to use symlinked daemon config path"),
                "unexpected stderr: {stderr}"
            ),
            other => panic!("expected subprocess error, got {other:?}"),
        }
        assert!(
            !target.exists(),
            "default config writer must not create the symlink target"
        );
        assert!(
            std::fs::symlink_metadata(paths.config_file())
                .expect("config metadata")
                .file_type()
                .is_symlink(),
            "existing symlink must be left untouched"
        );
    }

    /// T1 — upsert is idempotent and replaces a stale `[spawn_pool]` block
    /// without duplicating it or disturbing other sections.
    #[test]
    fn write_spawn_pool_config_replaces_and_preserves_other_sections() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).expect("mkdir config dir");
        // Seed a config with an unrelated section and a STALE spawn_pool block.
        std::fs::write(
            paths.config_file(),
            "[daemon]\nlog_level = \"info\"\ntrust_roots = \"abc\"\n\n\
             [spawn_pool]\n# stale\nuids = [999]\ngid = 1\n",
        )
        .expect("seed config");

        let prov = SpawnPoolProvisioning::SystemUsers {
            uids: vec![10010, 10011],
            gid: 10020,
        };
        // Run twice — must be idempotent.
        write_spawn_pool_config_inner(&paths, &prov).expect("write 1");
        write_spawn_pool_config_inner(&paths, &prov).expect("write 2");

        let text = std::fs::read_to_string(paths.config_file()).expect("read");
        // Unrelated section preserved.
        assert!(
            text.contains("[daemon]"),
            "daemon section preserved: {text}"
        );
        assert!(
            text.contains("trust_roots = \"abc\""),
            "daemon keys preserved: {text}"
        );
        // Exactly one spawn_pool header, stale uid gone, new uids present.
        assert_eq!(
            text.matches("[spawn_pool]").count(),
            1,
            "exactly one spawn_pool section: {text}"
        );
        assert!(!text.contains("uids = [999]"), "stale uids removed: {text}");
        assert!(text.contains("uids = [10010, 10011]"), "new uids: {text}");

        // The daemon's own config loader must accept the result.
        let cfg: toml::Value = toml::from_str(&text).expect("valid toml");
        assert!(cfg.get("spawn_pool").is_some(), "spawn_pool parses");
        assert!(cfg.get("daemon").is_some(), "daemon parses");
    }

    #[test]
    #[cfg(unix)]
    fn write_spawn_pool_config_preserves_existing_config_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).expect("mkdir config dir");
        std::fs::write(paths.config_file(), "[daemon]\nlog_level = \"info\"\n")
            .expect("seed config");
        std::fs::set_permissions(paths.config_file(), std::fs::Permissions::from_mode(0o640))
            .expect("set config mode");

        let prov = SpawnPoolProvisioning::SystemUsers {
            uids: vec![10010],
            gid: 10020,
        };
        write_spawn_pool_config_inner(&paths, &prov).expect("rewrite config");

        let meta = std::fs::metadata(paths.config_file()).expect("config metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o640,
            "atomic config rewrite must preserve existing mode"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_spawn_pool_config_refuses_symlinked_config() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).expect("mkdir config dir");
        let target = tmp.path().join("operator-config.toml");
        std::fs::write(&target, "[daemon]\nlog_level = \"debug\"\n").expect("seed target");
        symlink(&target, paths.config_file()).expect("symlink config");

        let prov = SpawnPoolProvisioning::SystemUsers {
            uids: vec![10010],
            gid: 10020,
        };
        let err = write_spawn_pool_config_inner(&paths, &prov)
            .expect_err("mutable config rewrite must reject symlinks");

        match err {
            InstallError::Subprocess { stderr, .. } => assert!(
                stderr.contains("refusing to use symlinked daemon config path"),
                "unexpected stderr: {stderr}"
            ),
            other => panic!("expected subprocess error, got {other:?}"),
        }
        let target_text = std::fs::read_to_string(&target).expect("read target");
        assert_eq!(
            target_text, "[daemon]\nlog_level = \"debug\"\n",
            "symlink target must not be mutated"
        );
    }

    /// T1 — `strip_spawn_pool_section` removes the section when it is the last
    /// block in the file (no trailing top-level header to terminate it).
    #[test]
    fn strip_spawn_pool_section_handles_trailing_section() {
        let text = "[daemon]\nlog_level = \"info\"\n\n[spawn_pool]\nuids = [1]\ngid = 2\n";
        let stripped = strip_spawn_pool_section(text);
        assert!(stripped.contains("[daemon]"));
        assert!(!stripped.contains("[spawn_pool]"));
        assert!(!stripped.contains("uids = [1]"));
    }

    // ─── ADR 155 + MACOS-PRIMITIVES Decision 5 install renderers ──

    /// T1 — Linux unit body renders pool args into `ExecStart`. The
    /// MACOS-PRIMITIVES Decision 5 brief locks `--pool-uid-base` and
    /// `--pool-size` as required helper-bin args; this test pins the
    /// install path as the producer.
    #[test]
    fn render_spawn_helper_unit_body_includes_pool_args() {
        let body = render_spawn_helper_unit_body(302, 10010, 8);
        assert!(
            body.contains("--pool-uid-base 10010"),
            "unit body must pass --pool-uid-base; got: {body}"
        );
        assert!(
            body.contains("--pool-size 8"),
            "unit body must pass --pool-size; got: {body}"
        );
        assert!(
            body.contains("--daemon-uid 302"),
            "unit body must pass --daemon-uid; got: {body}"
        );
        assert!(
            body.contains("emberd-spawn-helper-linux"),
            "unit body must reference Linux helper bin"
        );
    }

    /// T1 — macOS plist body renders pool args, ember-clients group,
    /// shim path, and expected shim hash. All four are load-bearing
    /// for production connectivity (Fix #1 — pool args), Fix #2 —
    /// group, and Fix #5 — shim hash from the brief.
    #[test]
    #[cfg(target_os = "macos")]
    fn render_spawn_helper_plist_body_includes_all_load_bearing_fields() {
        let body = render_spawn_helper_plist_body(302, 10010, 8, "deadbeef");
        assert!(
            body.contains("<string>--pool-uid-base</string>"),
            "plist must declare --pool-uid-base ProgramArguments entry"
        );
        assert!(
            body.contains("<string>10010</string>"),
            "plist must pass pool_uid_base value"
        );
        assert!(
            body.contains("<string>--pool-size</string>"),
            "plist must declare --pool-size ProgramArguments entry"
        );
        assert!(
            body.contains("<string>8</string>"),
            "plist must pass pool_size value"
        );
        assert!(
            body.contains("<string>ember-clients</string>"),
            "plist GroupName must be ember-clients (NOT wheel — Fix #2)"
        );
        assert!(
            !body.contains("<string>wheel</string>"),
            "plist must not contain GroupName=wheel; that was the Fix #2 bug"
        );
        assert!(
            body.contains("<string>--shim-path</string>"),
            "plist must pass --shim-path to helper"
        );
        assert!(
            body.contains("<string>/usr/local/libexec/emberd-spawn-shim</string>"),
            "plist must reference shim install location"
        );
        assert!(
            body.contains("<key>EXPECTED_SHIM_HASH</key>"),
            "plist must declare EXPECTED_SHIM_HASH env var"
        );
        assert!(
            body.contains("<string>deadbeef</string>"),
            "plist must render the supplied shim hash value"
        );
    }

    /// T1 — Linux unit body uses `ember_uid` (NOT `wheel`) and
    /// references the canonical socket path.
    #[test]
    fn render_spawn_helper_unit_body_references_canonical_socket() {
        let body = render_spawn_helper_unit_body(302, 10010, 8);
        assert!(
            body.contains("/var/run/emberd-spawn-helper.sock"),
            "unit body must bind canonical socket path"
        );
    }

    // ── T2: dseditgroup_tolerant_inner — mock-runner unit tests ──────────────
    //
    // These tests exercise `dseditgroup_tolerant_inner` directly, injecting
    // canned (exit_code, stderr, success) tuples and a checkmember closure
    // so no real `dseditgroup` subprocess is required.  All tests are
    // macOS-only because the function is `#[cfg(target_os = "macos")]`.

    /// T2 — happy path: dseditgroup exits 0, checkmember returns true.
    /// No tolerance branch is taken; Ok(()) is returned.
    #[test]
    #[cfg(target_os = "macos")]
    fn dseditgroup_tolerant_success_calls_postcondition_and_returns_ok() {
        let mut postcondition_called = false;
        let result = dseditgroup_tolerant_inner(
            "dseditgroup -o edit -a alice -t user ember-clients",
            || Ok((Some(0), String::new(), true)),
            || {
                postcondition_called = true;
                true // user IS a member
            },
        );
        assert!(
            result.is_ok(),
            "exit 0 + checkmember=true must succeed, got: {result:?}"
        );
        assert!(
            postcondition_called,
            "post-condition checker must be invoked even on clean success"
        );
    }

    /// T2 — macOS 26 "could not be replaced" surface (exit 73): the tolerance
    /// branch fires, the post-condition checker IS called, and because it
    /// returns true (user was already a member), Ok(()) is returned.
    ///
    /// This is the idempotent case: the operator was already in ember-clients
    /// from a previous install run; dseditgroup says "could not be replaced"
    /// because the record already exists, but membership is confirmed.
    #[test]
    #[cfg(target_os = "macos")]
    fn dseditgroup_tolerant_macos26_already_member_calls_postcondition_ok() {
        let mut postcondition_called = false;
        let result = dseditgroup_tolerant_inner(
            "dseditgroup -o edit -a alice -t user ember-clients",
            || {
                Ok((
                    Some(73),
                    "Operation cancelled because record could not be replaced".to_string(),
                    false,
                ))
            },
            || {
                postcondition_called = true;
                true // checkmember confirms membership
            },
        );
        assert!(
            result.is_ok(),
            "exit 73 + 'could not be replaced' + checkmember=true must be Ok, got: {result:?}"
        );
        assert!(
            postcondition_called,
            "post-condition checker must be called on the tolerated path"
        );
    }

    /// T2 — macOS 26 "could not be replaced" surface (exit 73) but the
    /// post-condition check returns false: the user was NOT actually added.
    /// Must return a clear InstallError, NOT Ok(()).
    ///
    /// This is the regression the fix targets: on macOS 26.4, dseditgroup
    /// can return this stderr+exit even when the add failed. Without the
    /// post-condition check the installer silently returned Ok(()), leaving
    /// the operator outside ember-clients.
    #[test]
    #[cfg(target_os = "macos")]
    fn dseditgroup_tolerant_macos26_postcondition_fails_returns_error() {
        let mut postcondition_called = false;
        let result = dseditgroup_tolerant_inner(
            "dseditgroup -o edit -a alice -t user ember-clients",
            || {
                Ok((
                    Some(73),
                    "Operation cancelled because record could not be replaced".to_string(),
                    false,
                ))
            },
            || {
                postcondition_called = true;
                false // checkmember: user is NOT a member
            },
        );
        assert!(
            result.is_err(),
            "exit 73 + 'could not be replaced' + checkmember=false must be Err, got: {result:?}"
        );
        assert!(
            postcondition_called,
            "post-condition checker must be called before returning"
        );
        // Error message must direct the operator to the manual fix.
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("dseditgroup -o edit") || msg.contains("ember-clients"),
            "error must reference the remediation command or group name, got: {msg}"
        );
    }

    /// T2 — unrelated non-zero exit (exit 1, generic failure) is NOT tolerated.
    /// The tolerance gate is exit_code==73 AND "could not be replaced"; a plain
    /// exit 1 from dseditgroup must propagate as a hard error without calling
    /// the post-condition checker.
    #[test]
    #[cfg(target_os = "macos")]
    fn dseditgroup_tolerant_unrelated_failure_propagates_without_postcondition() {
        let mut postcondition_called = false;
        let result = dseditgroup_tolerant_inner(
            "dseditgroup -o edit -a alice -t user ember-clients",
            || Ok((Some(1), "permission denied".to_string(), false)),
            || {
                postcondition_called = true;
                true
            },
        );
        assert!(
            result.is_err(),
            "exit 1 + unrelated stderr must be a hard error, got: {result:?}"
        );
        // Post-condition must NOT be called on unrelated failures — we don't
        // want to mask the real error with a checkmember output.
        assert!(
            !postcondition_called,
            "post-condition must NOT be called when the runner returns a hard failure"
        );
    }

    /// T2 — exit 73 alone (without "could not be replaced" in stderr) is NOT
    /// tolerated.  The check requires BOTH conditions so an unrelated exit-73
    /// path from dseditgroup doesn't get swallowed.
    #[test]
    #[cfg(target_os = "macos")]
    fn dseditgroup_tolerant_exit73_wrong_stderr_not_tolerated() {
        let mut postcondition_called = false;
        let result = dseditgroup_tolerant_inner(
            "dseditgroup -o edit -a alice -t user ember-clients",
            || Ok((Some(73), "some other error at exit 73".to_string(), false)),
            || {
                postcondition_called = true;
                true
            },
        );
        assert!(
            result.is_err(),
            "exit 73 with wrong stderr must not be tolerated, got: {result:?}"
        );
        assert!(
            !postcondition_called,
            "post-condition must not be called for non-tolerated failure"
        );
    }

    // ── T3: inspect_and_heal_ember_user_inner — partial-state collision ──────
    //
    // These tests exercise the inspect-and-heal step that gates the
    // sysadminctl -addUser call. They use injected closures (mirroring
    // the dseditgroup_tolerant_inner pattern shipped in #3470) so no
    // real `dscl` subprocess is required.

    /// T3 — user absent: reader returns Ok(None) for UniqueID → action
    /// is Create. Changer is never invoked.
    #[test]
    #[cfg(target_os = "macos")]
    fn inspect_and_heal_user_absent_returns_create() {
        let mut changer_calls: Vec<(String, String, String)> = Vec::new();
        let result = inspect_and_heal_ember_user_inner(
            |_prop| Ok(None), // UniqueID absent → user does not exist
            |prop, current, desired| {
                changer_calls.push((prop.to_string(), current.to_string(), desired.to_string()));
                Ok(())
            },
        );
        assert_eq!(
            result.expect("inspect must succeed when user is absent"),
            EmberUserInspectAction::Create,
            "absent user must yield Create action so caller runs sysadminctl -addUser"
        );
        assert!(
            changer_calls.is_empty(),
            "changer must NOT be called when the user is absent; got {changer_calls:?}"
        );
    }

    /// T3 — user present + canonical (uid in system range, home ==
    /// `/var/empty`, shell == `/usr/bin/false`): action is SkipHealthy
    /// and changer is NOT called.
    #[test]
    #[cfg(target_os = "macos")]
    fn inspect_and_heal_user_canonical_returns_skip_healthy() {
        let mut changer_calls: Vec<(String, String, String)> = Vec::new();
        let result = inspect_and_heal_ember_user_inner(
            |prop| match prop {
                "UniqueID" => Ok(Some("261".to_string())),
                "NFSHomeDirectory" => Ok(Some(EMBER_USER_HOME.to_string())),
                "UserShell" => Ok(Some(EMBER_USER_SHELL.to_string())),
                other => panic!("unexpected dscl property probe: {other}"),
            },
            |prop, current, desired| {
                changer_calls.push((prop.to_string(), current.to_string(), desired.to_string()));
                Ok(())
            },
        );
        assert_eq!(
            result.expect("canonical shape must succeed"),
            EmberUserInspectAction::SkipHealthy,
            "canonical shape must yield SkipHealthy so caller does NOT re-run sysadminctl"
        );
        assert!(
            changer_calls.is_empty(),
            "changer must NOT be called when the shape is already canonical; got {changer_calls:?}"
        );
    }

    /// T3 — user present + UID outside the system range: surface a hard
    /// InstallError with the manual remediation command in the message.
    /// Changer is NOT called (renumbering would orphan files).
    #[test]
    #[cfg(target_os = "macos")]
    fn inspect_and_heal_user_wrong_uid_returns_error_with_remediation() {
        let mut changer_calls: Vec<(String, String, String)> = Vec::new();
        let result = inspect_and_heal_ember_user_inner(
            |prop| match prop {
                // uid 503 → above EMBER_USER_MAX_SYSTEM_UID; came from a
                // different package or manual install
                "UniqueID" => Ok(Some("503".to_string())),
                "NFSHomeDirectory" => Ok(Some(EMBER_USER_HOME.to_string())),
                "UserShell" => Ok(Some(EMBER_USER_SHELL.to_string())),
                other => panic!("unexpected dscl property probe: {other}"),
            },
            |prop, current, desired| {
                changer_calls.push((prop.to_string(), current.to_string(), desired.to_string()));
                Ok(())
            },
        );
        let err = result.expect_err("uid out of system range must be a hard error");
        let msg = format!("{err}");
        // Remediation command must be in the message so the operator can
        // copy-paste it from the install failure surface.
        assert!(
            msg.contains("sudo dscl . -delete /Users/ember"),
            "error must include the dscl delete remediation; got: {msg}"
        );
        assert!(
            msg.contains("sudo dseditgroup -o delete -g ember"),
            "error must include the dseditgroup delete remediation; got: {msg}"
        );
        assert!(
            changer_calls.is_empty(),
            "changer must NOT be called when uid is out of range; got {changer_calls:?}"
        );
    }

    /// T3 — user present + wrong shell (other fields canonical): narrow
    /// corrective op fires via the changer closure, action is
    /// HealedThenSkip (so caller does NOT re-run sysadminctl), and the
    /// returned `changes` list mentions the UserShell edit.
    #[test]
    #[cfg(target_os = "macos")]
    fn inspect_and_heal_user_wrong_shell_calls_corrective_op_and_skips_create() {
        let mut changer_calls: Vec<(String, String, String)> = Vec::new();
        let result = inspect_and_heal_ember_user_inner(
            |prop| match prop {
                "UniqueID" => Ok(Some("261".to_string())),
                "NFSHomeDirectory" => Ok(Some(EMBER_USER_HOME.to_string())),
                // Wrong shell — divergence the inspector must heal.
                "UserShell" => Ok(Some("/bin/bash".to_string())),
                other => panic!("unexpected dscl property probe: {other}"),
            },
            |prop, current, desired| {
                changer_calls.push((prop.to_string(), current.to_string(), desired.to_string()));
                Ok(())
            },
        );
        let action = result.expect("narrow divergence must be healable");
        match action {
            EmberUserInspectAction::HealedThenSkip { changes } => {
                assert_eq!(
                    changes.len(),
                    1,
                    "exactly one corrective op expected (UserShell); got {changes:?}"
                );
                assert!(
                    changes[0].contains("UserShell"),
                    "change log must mention UserShell; got {:?}",
                    changes[0]
                );
                assert!(
                    changes[0].contains(EMBER_USER_SHELL),
                    "change log must mention canonical /usr/bin/false; got {:?}",
                    changes[0]
                );
            }
            other => panic!("expected HealedThenSkip, got {other:?}"),
        }
        assert_eq!(
            changer_calls.len(),
            1,
            "changer must be called exactly once (UserShell); got {changer_calls:?}"
        );
        let (prop, current, desired) = &changer_calls[0];
        assert_eq!(prop, "UserShell");
        assert_eq!(current, "/bin/bash");
        assert_eq!(desired, EMBER_USER_SHELL);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn create_ember_user_dscl_args_pin_reserved_uid_and_group() {
        let args = create_ember_user_dscl_args(450, 321);

        assert!(
            args.iter().any(|argv| {
                argv == &vec![
                    ".".to_string(),
                    "-create".to_string(),
                    "/Users/ember".to_string(),
                    "UniqueID".to_string(),
                    "450".to_string(),
                ]
            }),
            "create path must pin the allocated system uid, got: {args:?}"
        );
        assert!(
            args.iter().any(|argv| {
                argv == &vec![
                    ".".to_string(),
                    "-create".to_string(),
                    "/Users/ember".to_string(),
                    "PrimaryGroupID".to_string(),
                    "321".to_string(),
                ]
            }),
            "create path must set the resolved primary group gid, got: {args:?}"
        );
        assert!(
            args.iter().any(|argv| {
                argv == &vec![
                    ".".to_string(),
                    "-create".to_string(),
                    "/Users/ember".to_string(),
                    "RealName".to_string(),
                    EMBER_USER_REALNAME.to_string(),
                ]
            }),
            "create path must set RealName for the service account, got: {args:?}"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn allocate_ember_system_uid_prefers_first_free_high_system_uid() {
        let mut occupied = std::collections::BTreeSet::new();
        occupied.insert(450);
        occupied.insert(451);
        occupied.insert(452);

        let chosen = allocate_ember_system_uid_inner(|uid| occupied.contains(&uid))
            .expect("allocator must pick the first free system uid");

        assert_eq!(chosen, 453);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn allocate_ember_system_uid_errors_when_reserved_range_is_full() {
        let err = allocate_ember_system_uid_inner(|_| true)
            .expect_err("allocator must fail closed when every reserved uid is occupied");
        let msg = format!("{err}");
        assert!(
            msg.contains("no free macOS system uid available"),
            "error must explain the exhausted system-uid range, got: {msg}"
        );
    }

    // ── ADR 155 SLICE 2b — emberd-rpc sibling bootstrap (ember_rpc_sibling_bootstrap_landed) ──

    /// Serialize tests that mutate `EMBER_BRIDGE_BIND` — it is process-global,
    /// so two `rpc_sibling_should_bootstrap` tests racing under cargo's
    /// parallel runner would flake (and could poison `config.rs` env-reading
    /// tests run in the same process if not restored). Drop-restore guard.
    static BRIDGE_BIND_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct BridgeBindEnvGuard {
        previous: Option<String>,
    }
    impl BridgeBindEnvGuard {
        fn set(value: &str) -> Self {
            let previous = std::env::var("EMBER_BRIDGE_BIND").ok();
            unsafe { std::env::set_var("EMBER_BRIDGE_BIND", value) };
            Self { previous }
        }
        fn unset() -> Self {
            let previous = std::env::var("EMBER_BRIDGE_BIND").ok();
            unsafe { std::env::remove_var("EMBER_BRIDGE_BIND") };
            Self { previous }
        }
    }
    impl Drop for BridgeBindEnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(v) => std::env::set_var("EMBER_BRIDGE_BIND", v),
                    None => std::env::remove_var("EMBER_BRIDGE_BIND"),
                }
            }
        }
    }

    /// The launchd plist body must pin all four `EMBER_RPC_*` env vars to the
    /// daemon system paths (NOT the operator-home paths and NOT the sibling's
    /// own Config::default()). A wrong pin is a silent lane failure
    /// (cert-not-found → restart loop), so this asserts the exact strings.
    #[test]
    fn rpc_launchd_plist_body_pins_system_env() {
        let oh = Path::new("/home/test-operator");
        let body = render_rpc_launchd_plist_body(oh);
        let paths = crate::paths::DaemonPaths::system();

        for expected in [
            format!(
                "<key>EMBER_RPC_FORWARD_UDS</key><string>{}</string>",
                paths.run_dir.join("rpc.sock").display()
            ),
            format!(
                "<key>EMBER_RPC_SERVER_CERT</key><string>{}</string>",
                paths
                    .data_dir
                    .join("ember-rpc")
                    .join("server.crt")
                    .display()
            ),
            format!(
                "<key>EMBER_RPC_SERVER_KEY</key><string>{}</string>",
                paths
                    .data_dir
                    .join("ember-rpc")
                    .join("server.key")
                    .display()
            ),
            format!(
                "<key>EMBER_RPC_CA_CERT</key><string>{}</string>",
                paths.data_dir.join("bridge_ca.pem").display()
            ),
        ] {
            assert!(
                body.contains(&expected),
                "rpc plist must pin `{expected}`; got:\n{body}"
            );
        }
        assert!(
            !body.contains("/home/test-operator/.ember"),
            "rpc plist must not pin authority-space paths under operator home: {body}"
        );
        // Label + binary path sanity.
        assert!(body.contains("<string>sh.emberlink.rpc</string>"));
        assert!(body.contains("<string>/usr/local/bin/emberd-rpc-macos</string>"));
        assert!(body.contains("<key>UserName</key>        <string>ember</string>"));
        assert!(body.contains("<key>RunAtLoad</key>       <true/>"));
        assert!(body.contains("<key>KeepAlive</key>       <true/>"));
        // ThrottleInterval caps the respawn rate so a stuck sibling flaps at a
        // visible cadence rather than launchd's tight default (fail-loud parity
        // with the Linux StartLimit). (Added after adversarial review.)
        assert!(body.contains("<key>ThrottleInterval</key><integer>10</integer>"));
        assert!(body.contains("<string>/var/log/emberd-rpc.err</string>"));
        // All four pins must sit INSIDE the EnvironmentVariables <dict>.
        let env_close = body.find("</dict>").expect("env dict close");
        let ca_pos = body.find("EMBER_RPC_CA_CERT").expect("ca pin present");
        assert!(ca_pos < env_close, "pins must precede the env </dict>");
    }

    /// The systemd unit body must pin all four `EMBER_RPC_*` env vars to the
    /// daemon system paths via `Environment=` lines.
    #[test]
    fn rpc_systemd_unit_body_pins_system_env() {
        let oh = Path::new("/home/test-operator");
        let body = render_rpc_systemd_unit_body(oh);
        let paths = crate::paths::DaemonPaths::system();

        for expected in [
            format!(
                "Environment=EMBER_RPC_FORWARD_UDS={}",
                paths.run_dir.join("rpc.sock").display()
            ),
            format!(
                "Environment=EMBER_RPC_SERVER_CERT={}",
                paths
                    .data_dir
                    .join("ember-rpc")
                    .join("server.crt")
                    .display()
            ),
            format!(
                "Environment=EMBER_RPC_SERVER_KEY={}",
                paths
                    .data_dir
                    .join("ember-rpc")
                    .join("server.key")
                    .display()
            ),
            format!(
                "Environment=EMBER_RPC_CA_CERT={}",
                paths.data_dir.join("bridge_ca.pem").display()
            ),
        ] {
            assert!(
                body.contains(&expected),
                "rpc systemd unit must pin `{expected}`; got:\n{body}"
            );
        }
        assert!(
            !body.contains("/home/test-operator/.ember"),
            "rpc systemd unit must not pin authority-space paths under operator home: {body}"
        );
        assert!(body.contains("ExecStart=/usr/local/bin/emberd-rpc-linux"));
        assert!(body.contains("User=ember"));
        assert!(body.contains("Group=ember"));
    }

    /// The systemd unit must carry forward the full hardening set, add the 2c
    /// cert-hot-reload `ExecReload`, and — load-bearing — re-expose the daemon
    /// data/run dirs via `BindReadOnlyPaths`/`BindPaths` so the cert/socket
    /// paths are not hidden (and the lane does not silently fail).
    #[test]
    fn rpc_systemd_unit_body_carries_hardening_and_readonly_cert_paths() {
        let oh = Path::new("/home/test-operator");
        let body = render_rpc_systemd_unit_body(oh);
        let paths = crate::paths::DaemonPaths::system();

        for directive in [
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=tmpfs",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "RestrictNamespaces=true",
            "RestrictRealtime=true",
            "LockPersonality=true",
            "MemoryDenyWriteExecute=true",
        ] {
            assert!(
                body.contains(directive),
                "rpc systemd unit must carry hardening `{directive}`; got:\n{body}"
            );
        }

        // 2c cert hot-reload entry point.
        assert!(
            body.contains("ExecReload=/bin/kill -HUP $MAINPID"),
            "rpc systemd unit must declare ExecReload for cert hot-reload"
        );

        // Load-bearing: the Bind*Paths= must expose exactly the data
        // (read-only — certs) + run (read-write — forward-UDS connect)
        // dirs. Regressing to operator-home paths would silently
        // restart-loop every bridge-on Linux host.
        assert!(
            body.contains(&format!("BindReadOnlyPaths=-{}", paths.data_dir.display())),
            "must BIND data_dir read-only so the cert/key/ca are readable; got:\n{body}"
        );
        assert!(
            body.contains(&format!("BindPaths=-{}", paths.run_dir.display())),
            "must BIND run_dir read-write (BindPaths=) so the forward UDS is connectable; got:\n{body}"
        );
        // The `ProtectHome=tmpfs` directive assertion above is the regression
        // guard against a revert to `ProtectHome=true` (which can't re-expose
        // the cert path) — a revert would fail that assertion. (We can't assert
        // `!contains("ProtectHome=true")` here because the explanatory comment
        // in the rendered body legitimately mentions the rejected directive.)
    }

    /// Regression guard (adversarial review 2026-06-05): the INSTALLER's
    /// `EMBER_BRIDGE_BIND` env must be IGNORED — the launchd/systemd-launched
    /// daemon never sees it (not baked into its unit, not persisted to config),
    /// so honoring it would bootstrap a sibling for a daemon that boots
    /// bridge-OFF and crash-loops on the missing cert. Env set + NO config ⇒
    /// still disabled.
    ///
    /// Post-ADR-218: drives the `_inner` variant with a `for_test`
    /// `DaemonPaths` so the config-file lookup targets `<tmp>/config/
    /// config.toml` rather than the real system path.
    #[test]
    fn rpc_should_bootstrap_ignores_installer_env() {
        let _lock = BRIDGE_BIND_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _g = BridgeBindEnvGuard::set("127.0.0.1:8443");
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        assert!(
            !rpc_sibling_should_bootstrap_inner(&paths),
            "installer EMBER_BRIDGE_BIND must NOT bootstrap a sibling the daemon never backs"
        );
    }

    /// The config file decides regardless of any installer env value: a set
    /// `[daemon].bridge_bind` enables bootstrap even when `EMBER_BRIDGE_BIND` is
    /// set in the installer env — the env is ignored, config is authoritative.
    #[test]
    fn rpc_should_bootstrap_decided_by_config_not_env() {
        let _lock = BRIDGE_BIND_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _g = BridgeBindEnvGuard::set("");
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            paths.config_file(),
            "[daemon]\nbridge_bind = \"127.0.0.1:8443\"\n",
        )
        .unwrap();
        assert!(
            rpc_sibling_should_bootstrap_inner(&paths),
            "config bridge_bind must enable bootstrap; installer env is ignored"
        );
    }

    /// True from the config file's `[daemon].bridge_bind` when env is unset.
    #[test]
    fn rpc_should_bootstrap_true_from_config_when_env_unset() {
        let _lock = BRIDGE_BIND_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _g = BridgeBindEnvGuard::unset();
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DaemonPaths::for_test(tmp.path());
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            paths.config_file(),
            "[daemon]\nlog_level = \"info\"\nbridge_bind = \"0.0.0.0:8443\"\n",
        )
        .unwrap();
        assert!(rpc_sibling_should_bootstrap_inner(&paths));
    }

    /// False when env unset and config absent / empty bridge_bind.
    #[test]
    fn rpc_should_bootstrap_false_when_both_absent_or_empty() {
        let _lock = BRIDGE_BIND_ENV_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _g = BridgeBindEnvGuard::unset();

        // (a) no config file at all.
        let tmp_none = tempfile::tempdir().expect("tempdir");
        let paths_none = crate::paths::DaemonPaths::for_test(tmp_none.path());
        assert!(
            !rpc_sibling_should_bootstrap_inner(&paths_none),
            "no config + no env ⇒ disabled"
        );

        // (b) config present but bridge_bind empty string.
        let tmp_empty = tempfile::tempdir().expect("tempdir");
        let paths_empty = crate::paths::DaemonPaths::for_test(tmp_empty.path());
        std::fs::create_dir_all(&paths_empty.config_dir).unwrap();
        std::fs::write(paths_empty.config_file(), "[daemon]\nbridge_bind = \"\"\n").unwrap();
        assert!(
            !rpc_sibling_should_bootstrap_inner(&paths_empty),
            "empty config bridge_bind ⇒ disabled"
        );

        // (c) config present but no bridge_bind key.
        let tmp_absent = tempfile::tempdir().expect("tempdir");
        let paths_absent = crate::paths::DaemonPaths::for_test(tmp_absent.path());
        std::fs::create_dir_all(&paths_absent.config_dir).unwrap();
        std::fs::write(
            paths_absent.config_file(),
            "[daemon]\nlog_level = \"info\"\n",
        )
        .unwrap();
        assert!(
            !rpc_sibling_should_bootstrap_inner(&paths_absent),
            "absent config bridge_bind key ⇒ disabled"
        );
    }

    /// Unit-level coverage of the config-parse helper (no env, no temp file).
    #[test]
    fn bridge_bind_value_is_set_parses_correctly() {
        assert!(bridge_bind_value_is_set(
            "[daemon]\nbridge_bind = \"127.0.0.1:8443\"\n"
        ));
        assert!(!bridge_bind_value_is_set("[daemon]\nbridge_bind = \"\"\n"));
        assert!(!bridge_bind_value_is_set(
            "[daemon]\nlog_level = \"info\"\n"
        ));
        assert!(!bridge_bind_value_is_set(""));
        // Malformed TOML ⇒ not enabling (false), never panics.
        assert!(!bridge_bind_value_is_set("this is not = valid = toml ["));
        // Non-empty but NOT a SocketAddr ⇒ false — a malformed bridge_bind is a
        // hard daemon-startup abort, so we must not bootstrap a sibling for a
        // daemon that won't boot.
        assert!(!bridge_bind_value_is_set(
            "[daemon]\nbridge_bind = \"not-an-addr\"\n"
        ));
        assert!(!bridge_bind_value_is_set(
            "[daemon]\nbridge_bind = \"localhost:8443\"\n"
        ));
    }

    /// The rpc env-pin derivation must agree between the launchd + systemd
    /// renderers (they both call `rpc_env_pins`); assert the tuple directly.
    #[test]
    fn rpc_env_pins_derive_system_paths() {
        let (uds, cert, key, ca) = rpc_env_pins(Path::new("/Users/alice"));
        let paths = crate::paths::DaemonPaths::system();
        assert_eq!(
            uds,
            paths
                .run_dir
                .join("rpc.sock")
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(
            cert,
            paths
                .data_dir
                .join("ember-rpc")
                .join("server.crt")
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(
            key,
            paths
                .data_dir
                .join("ember-rpc")
                .join("server.key")
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(
            ca,
            paths
                .data_dir
                .join("bridge_ca.pem")
                .to_string_lossy()
                .into_owned()
        );
    }

    /// `install_emberd_rpc_binary_at` copies the sibling into the destination
    /// dir under the platform binary name (tempdir; no sudo). Mirrors
    /// `install_emberd_binary_at_copies_file`: the copy completes before the
    /// chown-to-root step, which fails under a non-root test runner; we verify
    /// the copy and tolerate only that chown/chmod failure.
    #[test]
    fn install_emberd_rpc_binary_at_copies_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("emberd-rpc-src");
        std::fs::write(&src, b"#!/bin/sh\necho rpc\n").expect("write src");
        let dst_dir = tmp.path().join("bin");

        let result = install_emberd_rpc_binary_at(&src, &dst_dir, EMBERD_RPC_BIN_NAME);

        let dst = dst_dir.join(EMBERD_RPC_BIN_NAME);
        assert!(
            dst.exists(),
            "rpc binary must be copied to dst even if a later step fails"
        );
        assert_eq!(
            std::fs::read(&dst).expect("read dst"),
            b"#!/bin/sh\necho rpc\n"
        );
        match result {
            Ok(()) => {}
            Err(InstallError::Subprocess { cmd, .. })
                if cmd.starts_with("chown ") || cmd.starts_with("chmod ") => {}
            Err(other) => panic!(
                "unexpected error variant (only chown/chmod failure expected under non-root): {other:?}"
            ),
        }
    }
}
