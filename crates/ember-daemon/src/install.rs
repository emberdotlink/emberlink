//! Separate-uid daemon install scaffolding (design).
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
/// Anchor: `implementation-note-232`
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
fn run(
    program: &str,
    args: &[&str],
    tolerate_already_exists: bool,
) -> Result<(), InstallError> {
    let cmd_string = format!("{} {}", program, args.join(" "));
    let output = Command::new(program).args(args).output().map_err(|e| {
        InstallError::Subprocess {
            cmd: cmd_string.clone(),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        }
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
/// (design): the dedicated `ember` system user exists.
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

/// Provision the `ember` system user + the `ember-clients` connect group.
///
/// **Idempotent.** Re-running on an already-provisioned machine returns
/// `Ok(())` without altering state — every step tolerates the platform's
/// "already exists" stderr signature.
///
/// On macOS:
/// - `dseditgroup -o create ember` — group create (idempotent).
/// - `sysadminctl -addUser ember -fullName "Emberlink Daemon" -home /var/empty -shell /usr/bin/false`
///   only when `id ember` reports the user is missing.
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

    // 2) ember user (only if missing)
    if !user_exists("ember") {
        run(
            "sysadminctl",
            &[
                "-addUser",
                "ember",
                "-fullName",
                "Emberlink Daemon",
                "-home",
                "/var/empty",
                "-shell",
                "/usr/bin/false",
            ],
            true,
        )?;
    }

    // 3) ember-clients connect group
    run("dseditgroup", &["-o", "create", "ember-clients"], true)?;

    // 4) add the ember user to ember-clients
    //
    // implementation-note-233: the
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
    let invoking_user = std::env::var("USER").unwrap_or_default();
    if !invoking_user.is_empty() {
        run(
            "dseditgroup",
            &[
                "-o",
                "edit",
                "-a",
                &invoking_user,
                "-t",
                "user",
                "ember-clients",
            ],
            true,
        )?;
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
        run(
            "usermod",
            &["-aG", "ember-clients", &invoking_user],
            true,
        )?;
    }

    Ok(())
}

/// Fallback for platforms other than macOS/Linux. The `emberd` install
/// flow is only supported on macOS + Linux (per design); other targets
/// surface a clear error rather than silently no-op.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn provision_ember_user() -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "provision_ember_user".to_string(),
        stderr: "unsupported platform: ember user provisioning is implemented only for macOS and Linux"
            .to_string(),
        exit_code: None,
    })
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

        // Remove destination before copy so that a pre-existing 0440 file
        // (from a previous install) does not cause Permission denied. The
        // file is invisible during the tiny window between remove and copy
        // because the parent dir is root:ember-clients 0750 — no other
        // process can race in that gap without already having root.
        if Path::new(dst_path).exists() {
            std::fs::remove_file(dst_path).map_err(|e| InstallError::Subprocess {
                cmd: format!("remove {dst_path}"),
                stderr: format!("remove failed: {e}"),
                exit_code: None,
            })?;
        }

        // Write then chmod then chown — safest ordering against partial-state
        // windows where the file is visible but not yet locked down.
        std::fs::copy(&src, dst_path).map_err(|e| InstallError::Subprocess {
            cmd: format!("copy {} -> {dst_path}", src.display()),
            stderr: format!("copy failed: {e}"),
            exit_code: None,
        })?;

        run("chmod", &["0440", dst_path], false)?;
        // implementation-note-233:
        // `root:ember-clients` (formerly `root:ember`) so the daemon — running
        // with `ember-clients` as primary group per the matching plist change
        // in `render_launchd_plist_body` — can read the credential.
        run("chown", &["root:ember-clients", dst_path], false)?;
    }

    Ok(())
}

/// Destination path for the `emberd` daemon binary. The LaunchDaemon plist's
/// `ProgramArguments` and the systemd unit's `ExecStart` both reference this
/// path; if the binary is missing the bootstrap silently exec-fails with
/// ENOENT and no `ember`-uid daemon process ever materializes.
const EMBERD_INSTALL_PATH: &str = "/usr/local/bin/emberd";

/// Parent directory of [`EMBERD_INSTALL_PATH`]. `mkdir -p` covers the rare
/// case where `/usr/local/` exists without `/usr/local/bin/` (fresh user
/// directories on some macOS images, minimal Linux base images).
const EMBERD_INSTALL_DIR: &str = "/usr/local/bin";

/// Env-var override naming an explicit path to the `emberd` binary that
/// install should publish. Honored when non-empty and free of `..` segments.
/// Set this in CI / package builds where the binary lives outside
/// `<cwd>/target/release/`.
const ENV_EMBERD_BIN_PATH: &str = "EMBER_EMBERD_BIN_PATH";

/// Resolve the `emberd` source binary to publish.
///
/// Resolution order:
/// 1. `EMBER_EMBERD_BIN_PATH` env var (non-empty, no `..` segments) —
///    authoritative override. Errors when set but the path does not exist.
/// 2. Sibling of `current_exe()` named `emberd`. `current_exe()` is
///    canonicalized first so a symlinked launcher (`~/.cargo/bin/ember -> target/release/ember`)
///    resolves to the real workspace dir where `emberd` was built alongside.
///
/// Errors with a copy-pasteable build hint when neither path resolves —
/// operators see "build `emberd` first with `cargo build --release -p
/// ember-daemon --bin emberd`, or set EMBER_EMBERD_BIN_PATH".
pub fn resolve_emberd_source() -> Result<PathBuf, InstallError> {
    if let Ok(raw) = std::env::var(ENV_EMBERD_BIN_PATH) {
        if !raw.is_empty() {
            let path = PathBuf::from(&raw);
            if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(InstallError::Subprocess {
                    cmd: "resolve_emberd_source".to_string(),
                    stderr: format!(
                        "{ENV_EMBERD_BIN_PATH}={raw:?} contains `..` segment — refused"
                    ),
                    exit_code: None,
                });
            }
            if !path.exists() {
                return Err(InstallError::Subprocess {
                    cmd: "resolve_emberd_source".to_string(),
                    stderr: format!(
                        "{ENV_EMBERD_BIN_PATH}={raw:?} does not exist"
                    ),
                    exit_code: None,
                });
            }
            return Ok(path);
        }
    }

    let current = std::env::current_exe().map_err(|e| InstallError::Subprocess {
        cmd: "current_exe".to_string(),
        stderr: format!("could not resolve current_exe: {e}"),
        exit_code: None,
    })?;
    let canonical = current.canonicalize().unwrap_or(current.clone());
    let parent = canonical.parent().ok_or_else(|| InstallError::Subprocess {
        cmd: "resolve_emberd_source".to_string(),
        stderr: format!("current_exe has no parent: {}", canonical.display()),
        exit_code: None,
    })?;
    let sibling = parent.join("emberd");
    if !sibling.exists() {
        return Err(InstallError::Subprocess {
            cmd: "resolve_emberd_source".to_string(),
            stderr: format!(
                "could not find `emberd` next to {}. Build with \
                 `cargo build --release -p ember-daemon --bin emberd`, \
                 or set {ENV_EMBERD_BIN_PATH} to an absolute path.",
                canonical.display()
            ),
            exit_code: None,
        });
    }
    Ok(sibling)
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
    if let (Ok(sc), Ok(dc)) = (src.canonicalize(), dst.canonicalize()) {
        if sc == dc {
            // Still re-apply mode + ownership so they converge if they
            // drifted (operator manually chmod-ed the file).
            run("chmod", &["0755", &dst_str], false)?;
            chown_emberd_binary(&dst_str)?;
            return Ok(());
        }
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
    run("chown", &[owner, dst_str], false)
}

/// Recursively chown every entry under `home/.ember` to `ember:ember-clients`
/// and tighten file modes.
///
/// **Why this walks the whole `.ember` tree instead of a hardcoded subdir list:**
///
/// A previous version enumerated `["vault", "grants", "sessions", "run",
/// "binaries"]` explicitly. The daemon's `DaemonConfig::default()` sets
/// `data_dir = ~/.ember/data` (where the SQLite event store lives), which was
/// absent from that list. After `sudo ember daemon install` ran this function,
/// `~/.ember/data/` was still owned by the operator uid, not `ember:ember`.
/// `emberd` (running as the `ember` system user) then opened the SQLite DB
/// read/write and hit EACCES → "attempt to write a readonly database". Fixing
/// the list to include `"data"` would close today's gap but reopen the hole
/// for any future directory `DaemonConfig` introduces.
///
/// The robust fix: walk **every** top-level entry that exists under `.ember/`
/// and chown it recursively so the set of covered paths tracks whatever the
/// daemon actually creates, without requiring a parallel update here.
///
/// **Idempotent.** The `.ember` root or any subdirectory may be absent; those
/// cases are skipped silently so re-running on an already-correct tree is a
/// no-op.
///
/// For each entry walked:
/// - `chown ember:ember-clients <path>`
/// - directories: `chmod 0750 <path>`
/// - files: `chmod 0640 <path>`
///
/// Requires elevated privileges (typically invoked under `sudo` from the
/// installer entry point).
///
/// ## Checkpoint
///
/// implementation-note-234
pub fn chown_ember_data_dirs(home: &Path) -> Result<(), InstallError> {
    chown_ember_data_dirs_inner(home, &mut |path, is_dir| {
        let path_str = path.to_string_lossy().into_owned();
        run("chown", &["ember:ember-clients", &path_str], false)?;
        // Signing-key material (daemon_identity.key, daemon_persona.key)
        // must be 0600 (owner-only) per the daemon's fail-closed check
        // in `infra::runtime` (implementation-note-164 F-S5-013).
        // The default 0640 lets the ember-clients group read non-secret
        // state (SQLite, snapshots, vault.salt, etc.) but is too
        // permissive for private keys.
        let is_private_key = !is_dir
            && path
                .extension()
                .and_then(|s| s.to_str())
                .map_or(false, |ext| ext == "key");
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
/// `apply_ownership` receives `(path, is_dir)` for every entry visited and
/// is responsible for chown + chmod. Production injects the real `run("chown",
/// ...)` / `run("chmod", ...)` shell-outs; tests inject a closure that records
/// which paths were visited.
fn chown_ember_data_dirs_inner<F>(home: &Path, apply_ownership: &mut F) -> Result<(), InstallError>
where
    F: FnMut(&Path, bool) -> Result<(), InstallError>,
{
    let ember_root = home.join(".ember");

    if !ember_root.exists() {
        // Nothing to chown — installer has not created the data tree yet.
        return Ok(());
    }

    // Walk every top-level entry under .ember/ and chown each recursively.
    // This covers data/ (SQLite + WAL + journal), vault/, grants/, sessions/,
    // run/, binaries/, and any future directories DaemonConfig introduces —
    // without requiring a parallel update to this list.
    for entry in std::fs::read_dir(&ember_root)? {
        let entry = entry?;
        chown_chmod_recursive_inner(&entry.path(), apply_ownership)?;
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
///   grant + receipt machinery; separate-uid posture (design); the
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
/// `implementation-note-235`: the shell-out to
/// `/usr/bin/security` passes the passphrase in `argv` for the duration
/// of the subprocess (~50ms on a single-user dev box). Long-term fix is
/// raw FFI to `SecKeychainAddGenericPassword` + `SecAccessCreate` with
/// an explicit permissive ACL, which avoids the argv leak entirely.
///
/// Anchor: `implementation-note-236`
pub fn provision_se_mek(home: &Path) -> Result<(), InstallError> {
    let data_dir = home.join(".ember").join("data");

    // 1) Ensure data dir exists. mkdir -p is idempotent.
    std::fs::create_dir_all(&data_dir).map_err(|e| InstallError::Subprocess {
        cmd: format!("mkdir -p {}", data_dir.display()),
        stderr: format!("create_dir_all failed: {e}"),
        exit_code: None,
    })?;

    // 2) On macOS + root, chown the dir to the daemon's uid/group so the
    //    daemon (running as ember via launchd) can read/write its own
    //    state files (SQLite event store, snapshots, etc.).
    #[cfg(target_os = "macos")]
    if nix::unistd::geteuid().is_root() {
        let s = data_dir.to_string_lossy().into_owned();
        run("chown", &["ember:ember-clients", &s], false)?;
        run("chmod", &["0750", &s], false)?;
    }

    // 3) Delete legacy SE-wrapped blobs from previous install attempts
    //    so they don't sit around as operator-confusing dead files. The
    //    daemon doesn't read them anymore. We don't error if they're
    //    absent (idempotent cleanup).
    let legacy_blob = data_dir.join(VAULT_MEK_FILENAME);
    if legacy_blob.exists() {
        if let Err(e) = std::fs::remove_file(&legacy_blob) {
            tracing::warn!(
                path = %legacy_blob.display(),
                error = %e,
                "could not delete legacy vault-mek.bin; install proceeding"
            );
        } else {
            tracing::info!(path = %legacy_blob.display(), "removed legacy SE-wrapped blob");
        }
    }
    let legacy_poison = data_dir.join(".vault-mek-provision-failed");
    if legacy_poison.exists() {
        let _ = std::fs::remove_file(&legacy_poison);
    }

    // 4) Write the MEK passphrase to System.keychain (macOS + root only).
    //    The `security add-generic-password` step against System.keychain
    //    requires root; non-root invocations (e.g., `sudo -u ember ...`
    //    test path) skip this and return Ok so the install can be
    //    partially exercised in unit tests without touching the real
    //    system keychain.
    #[cfg(target_os = "macos")]
    if nix::unistd::geteuid().is_root() {
        provision_vault_mek_in_system_keychain()?;
    } else {
        tracing::info!(
            "non-root install — skipping System.keychain write (the canonical install runs as root via sudo)"
        );
    }

    Ok(())
}

/// Write the vault MEK passphrase to `/Library/Keychains/System.keychain`
/// as a `kSecClassGenericPassword` item with a permissive partition list,
/// idempotent on item presence.
///
/// **Idempotent.** If a vault-MEK item already exists in System.keychain
/// (a previous install ran successfully), the function returns `Ok(())`
/// without overwriting — overwriting would destroy access to any vault
/// data encrypted under the existing MEK.
///
/// Requires root (`SecKeychainAddGenericPassword` against System.keychain
/// requires write authority that non-root processes don't have).
///
/// ## Implementation
///
/// We shell out to `/usr/bin/security add-generic-password -A` because
/// `security-framework`'s `SecKeychain::add_generic_password` doesn't
/// expose a way to set the `-A` permissive partition list — the
/// underlying `SecKeychainAddGenericPassword` FFI passes `NULL` for the
/// `SecAccess` parameter, which gives the item a default ACL of
/// "this app only," which would deny the daemon (different binary)
/// access.
///
/// The trade-off: the `security` CLI puts the passphrase in `argv` for
/// the duration of the subprocess. On a single-user dev box running as
/// root, the audience is "processes I'm already trusting." Acceptable
/// for the dev0 wedge. Long-term: raw FFI to
/// `SecKeychainAddGenericPassword` + `SecAccessCreate` with an explicit
/// permissive ACL. Filed as `implementation-note-235`.
#[cfg(target_os = "macos")]
fn provision_vault_mek_in_system_keychain() -> Result<(), InstallError> {
    use crate::infra::vault_macos_se::{
        SYSTEM_KEYCHAIN_PATH, VAULT_MEK_ACCOUNT, VAULT_MEK_SERVICE,
    };
    use security_framework::os::macos::keychain::SecKeychain;

    // Idempotency check — if the item is already present, do NOT
    // overwrite (would orphan any vault data encrypted under the
    // existing MEK).
    let keychain = SecKeychain::open(SYSTEM_KEYCHAIN_PATH).map_err(|e| InstallError::Subprocess {
        cmd: format!("SecKeychain::open({SYSTEM_KEYCHAIN_PATH})"),
        stderr: format!("{e}"),
        exit_code: None,
    })?;
    if keychain
        .find_generic_password(VAULT_MEK_SERVICE, VAULT_MEK_ACCOUNT)
        .is_ok()
    {
        tracing::info!(
            service = VAULT_MEK_SERVICE,
            account = VAULT_MEK_ACCOUNT,
            "vault MEK already present in System.keychain — skipping (idempotent)"
        );
        return Ok(());
    }

    // Generate 32 cryptographically-random bytes and hex-encode to a
    // 64-char ASCII passphrase. Matches the format the daemon's read
    // path expects (`plaintext.len() == 64`).
    let mut mek_bytes = [0u8; 32];
    getrandom::fill(&mut mek_bytes).map_err(|e| InstallError::Subprocess {
        cmd: "getrandom::fill".to_string(),
        stderr: format!("OS entropy failure: {e}"),
        exit_code: None,
    })?;
    let hex_passphrase = hex::encode(mek_bytes);

    // Shell out to `security add-generic-password -A`. `-A` is the
    // permissive partition list (any signing identity can access the
    // item without prompt). This is what Apple's own setup tools use
    // for System.keychain items intended to be shared between system
    // daemons (apsd's APN tokens, eapolclient's WiFi PSKs, etc.).
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-A",
            "-s",
            VAULT_MEK_SERVICE,
            "-a",
            VAULT_MEK_ACCOUNT,
            "-w",
            &hex_passphrase,
            SYSTEM_KEYCHAIN_PATH,
        ])
        .output()
        .map_err(|e| InstallError::Subprocess {
            cmd: format!(
                "/usr/bin/security add-generic-password -A -s {VAULT_MEK_SERVICE} -a {VAULT_MEK_ACCOUNT} {SYSTEM_KEYCHAIN_PATH}"
            ),
            stderr: format!("spawn failed: {e}"),
            exit_code: None,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(InstallError::Subprocess {
            cmd: format!(
                "/usr/bin/security add-generic-password -A -s {VAULT_MEK_SERVICE} -a {VAULT_MEK_ACCOUNT} {SYSTEM_KEYCHAIN_PATH}"
            ),
            stderr,
            exit_code: output.status.code(),
        });
    }

    tracing::info!(
        service = VAULT_MEK_SERVICE,
        account = VAULT_MEK_ACCOUNT,
        path = SYSTEM_KEYCHAIN_PATH,
        "vault MEK provisioned in System.keychain"
    );
    Ok(())
}


// Plist + systemd unit bodies are rendered with the operator's home dir
// baked in as the daemon's HOME env var. The daemon resolves
// `~/.ember/{vault,grants,sessions,run,binaries}` at startup via
// `dirs_next::home_dir()`, which under launchd/systemd `User=ember` would
// resolve to `/var/empty` (the ember system user's home) — pointing the
// daemon at an empty tree instead of the operator's chowned-to-ember
// data. Baking HOME=<operator_home> at install time aligns the daemon's
// runtime view with the chown step's target. See design §macOS install.

/// Path on disk for the macOS LaunchDaemon plist.
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.plist";

/// Path on disk for the Linux systemd unit.
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/emberd.service";

/// Returns the rendered launchd plist body with the operator's HOME
/// baked into `EnvironmentVariables`. Tests assert against this helper
/// so the writer and the assertion read from the same source.
///
/// `dead_code` allowed because on a Linux non-test build there is no
/// caller (the macOS impl is excluded and tests don't compile).
#[allow(dead_code)]
pub(crate) fn render_launchd_plist_body(operator_home: &Path) -> String {
    let home = operator_home.display();
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
             <key>HOME</key><string>{home}</string>\n    \
             <key>EMBER_APP_PEM_PATH</key><string>/etc/emberlink/ember-engine-app.pem</string>\n    \
             <key>EMBER_APP_ENV_PATH</key><string>/etc/emberlink/ember-engine.env</string>\n  \
           </dict>\n  \
           <key>ProgramArguments</key>\n  \
           <array>\n    \
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

/// Returns the rendered systemd unit body with the operator's HOME baked
/// into `Environment=HOME=...`. Tests assert against this helper so the
/// writer and the assertion read from the same source.
///
/// `dead_code` allowed because on a macOS non-test build there is no
/// caller (the Linux impl is excluded and tests don't compile).
#[allow(dead_code)]
pub(crate) fn render_systemd_unit_body(operator_home: &Path) -> String {
    let home = operator_home.display();
    format!(
        "[Unit]\n\
         Description=Emberlink Grant Warden daemon\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=ember\n\
         Group=ember\n\
         Environment=HOME={home}\n\
         Environment=EMBER_APP_PEM_PATH=/etc/emberlink/ember-engine-app.pem\n\
         Environment=EMBER_APP_ENV_PATH=/etc/emberlink/ember-engine.env\n\
         ExecStart=/usr/local/bin/emberd --foreground\n\
         Restart=on-failure\n\
         RestartSec=5\n\
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
/// helper reads `$SUDO_USER` (falling back to `$USER` for the run-as-root-
/// directly case) and resolves that user's home via `getpwnam_r`.
///
/// Returns `InstallError::Subprocess` with a clear hint when the install
/// is being run as root with no `$SUDO_USER` to anchor to — that's the
/// "logged in as root directly" case the install isn't designed for.
pub fn resolve_operator_home() -> Result<PathBuf, InstallError> {
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();

    if user.is_empty() || user == "root" {
        return Err(InstallError::Subprocess {
            cmd: "resolve_operator_home".to_string(),
            stderr: format!(
                "could not resolve invoking-operator home: SUDO_USER={:?} USER={:?}. \
                 Run via `sudo ember daemon install` from a regular user shell — \
                 not from a root login.",
                std::env::var("SUDO_USER").ok(),
                std::env::var("USER").ok()
            ),
            exit_code: None,
        });
    }

    home_for_user(&user).ok_or_else(|| InstallError::Subprocess {
        cmd: "resolve_operator_home".to_string(),
        stderr: format!("getpwnam_r for {user:?} returned no home directory"),
        exit_code: None,
    })
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
/// into the system domain (per design §macOS install).
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
    // Publish the emberd binary first — the plist's ProgramArguments
    // references /usr/local/bin/emberd; bootstrap silently exec-fails
    // with ENOENT if the binary is missing.
    install_emberd_binary()?;

    let path = Path::new(LAUNCHD_PLIST_PATH);
    let body = render_launchd_plist_body(operator_home);

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

    if !already_matches || !is_launchd_service_loaded() {
        std::fs::write(path, &body).map_err(|e| InstallError::Subprocess {
            cmd: format!("write {LAUNCHD_PLIST_PATH}"),
            stderr: format!("write failed: {e}"),
            exit_code: None,
        })?;

        run("chmod", &["0644", LAUNCHD_PLIST_PATH], false)?;

        // bootout — tolerate "not currently bootstrapped" (exit 113 or
        // stderr containing "Could not find specified service"). This
        // is the macOS-launchctl analogue of `groupadd --force`.
        bootout_tolerant()?;

        // Pre-create the log files with ember:ember ownership BEFORE bootstrap.
        // launchd opens StandardErrorPath/StandardOutPath as root then passes
        // the fds to the daemon; if the files don't exist the ember user can't
        // create them (mode 755 root:wheel on /var/log) and launchd surfaces
        // EX_CONFIG (78), KeepAlive respawns, daemon never starts.
        ensure_emberd_log_paths()?;

        run(
            "launchctl",
            &["bootstrap", "system", LAUNCHD_PLIST_PATH],
            false,
        )?;
    }

    Ok(())
}

/// True if `launchctl print system/sh.emberlink.daemon` succeeds (exit
/// code 0), meaning the daemon is currently registered with launchd in
/// the system domain. Used by [`install_launchd_plist`]'s idempotency
/// check to detect the "matching plist on disk but service not loaded"
/// case (e.g., after an operator manually unloaded the service or after
/// a previous install's bootout succeeded but its bootstrap failed).
#[cfg(target_os = "macos")]
fn is_launchd_service_loaded() -> bool {
    let label = "system/sh.emberlink.daemon";
    Command::new("launchctl")
        .args(["print", label])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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
/// ## Checkpoint
///
/// implementation-note-237
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
/// ## Checkpoint
///
/// implementation-note-238
#[cfg(target_os = "macos")]
pub fn ensure_emberd_log_paths() -> Result<(), InstallError> {
    ensure_emberd_log_paths_inner(
        Path::new(EMBERD_LOG_ERR),
        Path::new(EMBERD_LOG_OUT),
        || ember_user_uid_gid(),
        |path, uid, gid| {
            use std::ffi::CString;
            let path_c = CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|e| InstallError::Subprocess {
                    cmd: format!("chown {}", path.display()),
                    stderr: format!("path contains NUL: {e}"),
                    exit_code: None,
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
) -> Result<(), InstallError>
where
    L: FnOnce() -> Option<(libc::uid_t, libc::gid_t)>,
    C: FnMut(&Path, libc::uid_t, libc::gid_t) -> Result<(), InstallError>,
{
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::PermissionsExt;

    // Fail clearly when the ember user hasn't been provisioned yet.
    let (uid, gid) = lookup_uid_gid().ok_or_else(|| InstallError::Subprocess {
        cmd: "ensure_emberd_log_paths".to_string(),
        stderr: "ember system user does not exist — run `provision_ember_user` first".to_string(),
        exit_code: None,
    })?;

    for path in &[err_path, out_path] {
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
        std::fs::set_permissions(path, Permissions::from_mode(0o644))
            .map_err(|e| InstallError::Subprocess {
                cmd: format!("chmod 0644 {}", path.display()),
                stderr: format!("set_permissions failed: {e}"),
                exit_code: None,
            })?;

        chown_file(path, uid, gid)?;
    }

    Ok(())
}

/// Non-macOS fallback for [`install_launchd_plist`]. The launchd flow
/// is meaningful only on macOS; surface a clear error rather than
/// silently no-op.
#[cfg(not(target_os = "macos"))]
pub fn install_launchd_plist(_operator_home: &Path) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_launchd_plist".to_string(),
        stderr: "unsupported platform: launchd plist install is macOS-only"
            .to_string(),
        exit_code: None,
    })
}

/// Install the `emberd.service` systemd unit at
/// `/etc/systemd/system/emberd.service` and enable it (per design
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
        std::fs::write(path, &body).map_err(|e| InstallError::Subprocess {
            cmd: format!("write {SYSTEMD_UNIT_PATH}"),
            stderr: format!("write failed: {e}"),
            exit_code: None,
        })?;

        run("chmod", &["0644", SYSTEMD_UNIT_PATH], false)?;
    }

    run("systemctl", &["daemon-reload"], false)?;
    run("systemctl", &["enable", "--now", "emberd.service"], false)?;

    Ok(())
}

/// Non-Linux fallback for [`install_systemd_unit`]. The systemd flow
/// is meaningful only on Linux; surface a clear error rather than
/// silently no-op.
#[cfg(not(target_os = "linux"))]
pub fn install_systemd_unit(_operator_home: &Path) -> Result<(), InstallError> {
    Err(InstallError::Subprocess {
        cmd: "install_systemd_unit".to_string(),
        stderr: "unsupported platform: systemd unit install is Linux-only"
            .to_string(),
        exit_code: None,
    })
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

    /// T1 unit — the chown traversal is a no-op on an empty dir tree.
    /// We point `chown_ember_data_dirs` at a tmpdir that has no `.ember`
    /// subdir at all; every known subdir is missing so the function
    /// short-circuits per the idempotent-skip branch and returns Ok.
    #[test]
    fn chown_ember_data_dirs_on_empty_dir_is_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = chown_ember_data_dirs(tmp.path());
        assert!(
            result.is_ok(),
            "empty home (no .ember tree) should be a no-op, got {:?}",
            result
        );
    }

    /// T1 unit — calling on a home that has `.ember/` but none of the
    /// expected subdirs is also a no-op (all five are missing → all five
    /// hit the idempotent-skip branch).
    #[test]
    fn chown_ember_data_dirs_on_missing_subdirs_is_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(tmp.path().join(".ember")).expect("mkdir .ember");
        let result = chown_ember_data_dirs(tmp.path());
        assert!(
            result.is_ok(),
            "home with empty .ember/ should be a no-op, got {:?}",
            result
        );
    }

    /// T1 — chown_ember_data_dirs_inner visits `data/` and the file inside it.
    ///
    /// Regression: the previous hardcoded-subdir implementation did not include
    /// `"data"` in its list, so `~/.ember/data/` (where the SQLite event store
    /// lives per `DaemonConfig::default().data_dir`) was never chowned. emberd
    /// running as the `ember` system user hit EACCES on the DB → "attempt to
    /// write a readonly database". This test pins the fix: a tree that contains
    /// `data/` with a file inside it MUST be visited by the chown walk.
    ///
    /// Uses closure injection so no root privileges are required.
    #[test]
    fn chown_ember_data_dirs_includes_daemon_data_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ember_root = tmp.path().join(".ember");
        let data_dir = ember_root.join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir .ember/data");
        // Simulate the SQLite DB file and WAL file that the daemon creates
        // inside data/.
        std::fs::write(data_dir.join("ember.db"), b"fake-sqlite-header")
            .expect("write ember.db");
        std::fs::write(data_dir.join("ember.db-wal"), b"fake-wal")
            .expect("write ember.db-wal");

        let mut visited: Vec<std::path::PathBuf> = Vec::new();
        let result = chown_ember_data_dirs_inner(tmp.path(), &mut |path, _is_dir| {
            visited.push(path.to_path_buf());
            Ok(())
        });
        assert!(result.is_ok(), "chown_ember_data_dirs_inner failed: {:?}", result);

        // data/ itself must be visited.
        assert!(
            visited.contains(&data_dir),
            "data/ dir was not visited; visited={:?}",
            visited
        );

        // Files inside data/ must also be visited (recursive walk).
        let db_path = data_dir.join("ember.db");
        let wal_path = data_dir.join("ember.db-wal");
        assert!(
            visited.contains(&db_path),
            "ember.db was not visited; visited={:?}",
            visited
        );
        assert!(
            visited.contains(&wal_path),
            "ember.db-wal was not visited; visited={:?}",
            visited
        );
    }

    /// T1 — chown_ember_data_dirs_inner visits the legacy dirs (vault, grants,
    /// sessions, run, binaries) so the fix for the missing `data/` entry does
    /// not regress ownership of the pre-existing subdirectory set.
    #[test]
    fn chown_ember_data_dirs_regression_legacy_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ember_root = tmp.path().join(".ember");

        // Create the legacy subdirs with a checkpoint file in each.
        let legacy = ["vault", "grants", "sessions", "run", "binaries"];
        for name in legacy.iter() {
            let dir = ember_root.join(name);
            std::fs::create_dir_all(&dir).expect("mkdir legacy subdir");
            std::fs::write(dir.join("checkpoint"), b"x").expect("write checkpoint");
        }

        let mut visited: Vec<std::path::PathBuf> = Vec::new();
        let result = chown_ember_data_dirs_inner(tmp.path(), &mut |path, _is_dir| {
            visited.push(path.to_path_buf());
            Ok(())
        });
        assert!(result.is_ok(), "chown_ember_data_dirs_inner failed: {:?}", result);

        for name in legacy.iter() {
            let dir = ember_root.join(name);
            assert!(
                visited.contains(&dir),
                "{name}/ dir was not visited; visited={:?}",
                visited
            );
            let checkpoint = dir.join("checkpoint");
            assert!(
                visited.contains(&checkpoint),
                "{name}/checkpoint was not visited; visited={:?}",
                visited
            );
        }
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

    /// T1 — under Plan 2A, `provision_se_mek` creates the data dir,
    /// chowns it to `ember:ember-clients` (when root), and DELETES any
    /// orphaned legacy `vault-mek.bin` from earlier SE-attempt installs.
    /// The MEK now lives in `/Library/Keychains/System.keychain`, not
    /// on disk. Under non-root test runners the System.keychain write
    /// is skipped (only the canonical `sudo ember daemon install` does
    /// the write).
    #[test]
    fn provision_se_mek_creates_data_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = provision_se_mek(tmp.path());

        let data_dir = tmp.path().join(".ember").join("data");
        assert!(
            data_dir.is_dir(),
            "~/.ember/data/ must be created; provision_se_mek returned {result:?}"
        );

        // `vault-mek.bin` MUST NOT exist after install — Plan 2A stores
        // the MEK in System.keychain instead. (This test starts with no
        // legacy blob; the orphan-cleanup path is exercised in
        // `provision_se_mek_idempotent_no_root` below.)
        let mek_path = data_dir.join("vault-mek.bin");
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
                "unexpected error from provision_se_mek (only chown/chmod failures expected under non-root): {other:?}"
            ),
        }
    }

    /// T1 — `provision_se_mek` cleans up legacy `vault-mek.bin` blobs
    /// from earlier SE-attempt installs. The pre-existing blob is the
    /// product of a previous failed install lineage (SE-in-DPK or
    /// Plan-J) and is no longer read by the daemon under Plan 2A.
    /// Leaving it on disk would just confuse operators.
    #[test]
    fn provision_se_mek_idempotent_no_root() {
        let tmp = tempfile::tempdir().expect("tempdir");

        // Pre-create the data dir + a stale legacy blob.
        let data_dir = tmp.path().join(".ember").join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data");
        let mek_path = data_dir.join("vault-mek.bin");
        let checkpoint = [0xABu8; 32];
        std::fs::write(&mek_path, &checkpoint).expect("write checkpoint");

        let result = provision_se_mek(tmp.path());
        match result {
            Ok(()) => {}
            Err(InstallError::Subprocess { cmd, .. })
                if cmd.starts_with("chown ") || cmd.starts_with("chmod ") => {}
            Err(other) => panic!("unexpected error on idempotent path: {other:?}"),
        }

        // Plan 2A cleans up the legacy blob. The MEK now lives in
        // System.keychain instead.
        assert!(
            !mek_path.exists(),
            "Plan 2A install must remove the legacy vault-mek.bin orphan"
        );
    }

    /// The launchd plist body the writer emits must include the
    /// EnvironmentVariables.HOME block so the daemon (running as the
    /// `ember` system uid) resolves `~/.ember/...` to the operator's
    /// chowned data dir instead of `/var/empty`. It must also include
    /// EMBER_APP_PEM_PATH and EMBER_APP_ENV_PATH so the daemon can read
    /// the GH App credentials from `/etc/emberlink/` at boot without
    /// falling back to the ember uid's (empty) $HOME. Guards against
    /// silent drift between the rendered text and design.
    ///
    /// Build the expected text by joining lines with `\n` rather than
    /// using string-continuation (`\\\n`), which would collapse the
    /// significant two-space indentation inside `<dict>...</dict>`.
    #[test]
    fn plist_body_matches_adr_131() {
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
            "    <key>HOME</key><string>/home/test-operator</string>",
            "    <key>EMBER_APP_PEM_PATH</key><string>/etc/emberlink/ember-engine-app.pem</string>",
            "    <key>EMBER_APP_ENV_PATH</key><string>/etc/emberlink/ember-engine.env</string>",
            "  </dict>",
            "  <key>ProgramArguments</key>",
            "  <array>",
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
    }

    /// The systemd unit body the writer emits must include
    /// `Environment=HOME=<operator_home>` so the daemon (running as the
    /// `ember` system uid via `User=ember`) resolves `~/.ember/...` to
    /// the operator's chowned data dir. It must also include
    /// EMBER_APP_PEM_PATH and EMBER_APP_ENV_PATH so the daemon can read
    /// GH App credentials from `/etc/emberlink/` at boot. Guards against
    /// silent drift between the rendered text and design.
    #[test]
    fn systemd_unit_body_matches_adr_131() {
        let expected = [
            "[Unit]",
            "Description=Emberlink Grant Warden daemon",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            "User=ember",
            "Group=ember",
            "Environment=HOME=/home/test-operator",
            "Environment=EMBER_APP_PEM_PATH=/etc/emberlink/ember-engine-app.pem",
            "Environment=EMBER_APP_ENV_PATH=/etc/emberlink/ember-engine.env",
            "ExecStart=/usr/local/bin/emberd --foreground",
            "Restart=on-failure",
            "RestartSec=5",
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
    }

    /// The HOME-resolution helper handles the empty-user case cleanly,
    /// regardless of whether it's invoked from a sudo context or not.
    /// We can't reliably test the success path in a unit test (would
    /// need to mock `getpwnam_r`), but the empty-user error path is
    /// the load-bearing safety net — confirm it fires.
    #[test]
    fn resolve_operator_home_refuses_root_only_invocation() {
        // Drop SUDO_USER + force USER=root for this thread; restore on exit.
        // T1 unit — std::env mutation requires a process-wide lock for safety
        // against parallel test threads; gate behind the existing test lock.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior_sudo = std::env::var("SUDO_USER").ok();
        let prior_user = std::env::var("USER").ok();
        // SAFETY: std::env::* are unsafe in Rust 2024; we hold PROCESS_TEST_LOCK
        // for the duration so no other thread mutates env concurrently.
        unsafe {
            std::env::remove_var("SUDO_USER");
            std::env::set_var("USER", "root");
        }

        let result = resolve_operator_home();

        // Restore environment.
        unsafe {
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
            "resolve_operator_home must refuse when only USER=root is set, got {:?}",
            result
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
    fn install_pem_to_etc_into(
        operator_home: &Path,
        dest_dir: &Path,
    ) -> Result<(), InstallError> {
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

            // Remove before copy so a pre-existing 0440 file doesn't cause
            // Permission denied on the write (mirrors install_pem_to_etc).
            // Removal only needs write on the parent dir — no need to relax
            // the file's own mode first.
            if dst.exists() {
                std::fs::remove_file(&dst).map_err(|e| InstallError::Subprocess {
                    cmd: format!("remove {}", dst.display()),
                    stderr: format!("remove failed: {e}"),
                    exit_code: None,
                })?;
            }

            std::fs::copy(&src, &dst).map_err(|e| InstallError::Subprocess {
                cmd: format!("copy {} -> {}", src.display(), dst.display()),
                stderr: format!("copy failed: {e}"),
                exit_code: None,
            })?;

            // Set mode 0440 on the file.
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o440))?;
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
        std::fs::write(src_config.join("ember-engine-app.pem"), b"PEM v1")
            .expect("write pem");
        std::fs::write(src_config.join("ember-engine.env"), b"ENV=1")
            .expect("write env");

        let dest_dir = dest_tmp.path().join("etc-emberlink");

        install_pem_to_etc_into(operator_tmp.path(), &dest_dir)
            .expect("first call");

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
        assert!(dest_dir.exists(), "dest dir must be created even when source is missing");

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

    // ── implementation-note-239 — resolve_emberd_source + install_emberd_binary_at ────

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
                    stderr.contains("could not find `emberd`")
                        || stderr.contains("current_exe"),
                    "empty env var should fall through to sibling lookup, got: {stderr}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
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

        assert!(
            result.is_ok(),
            "ensure_emberd_log_paths_inner must succeed with mocked ember user, got: {result:?}"
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
            assert_eq!(*uid, mock_uid, "uid must match mocked ember uid for {}", path.display());
            assert_eq!(*gid, mock_gid, "gid must match mocked ember gid for {}", path.display());
        }
        let chowned_paths: Vec<&std::path::Path> = chowned.iter().map(|(p, _, _)| p.as_path()).collect();
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
            || None, // ember user does not exist
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
}
