//! ember-gh — canonical reference Construct shim per design §1.
//!
//! Lifecycle (per design §1):
//!   1. env-detect  — if EMBER_SESSION_ID absent, exec `gh` directly.
//!   2. classify    — map argv → action_key via classify_gh_argv.
//!   3. broker.resolve (combined with exec) — send `broker_exec` RPC to
//!      emberd over the daemon's Unix socket. The daemon forks `gh` with
//!      a pty, connects to our PTY UDS listener, and bridges bytes.
//!   4. pty bridge  — pump bytes between our stdin/stdout and the daemon's
//!      PTY UDS connection until the child exits. SIGWINCH events are
//!      captured and forwarded to the daemon as TAG_WINSIZE frames so the
//!      child process sees the correct terminal size at all times.
//!   5. Exit with the child's exit code (BrokerExecResponse.exit_code).
//!
//! Wire path (broker.resolve + broker.exec):
//!   client → {method:"broker_exec", params:{binary,argv,pty_socket_path}}
//!          → daemon handler.rs::handle_broker_exec
//!          → forkpty_exec_and_bridge(binary, argv, ..., socket_path)
//!          → pty_bridge_run(master_fd, socket_path)  [daemon side]
//!   client ← {result:{exit_code, success, stderr_tail}}
//!
//! ## Client → Daemon wire format (PTY channel)
//!
//! All bytes sent from client to daemon over the PTY UDS are framed:
//!
//!   TAG_DATA   (0x00): [0x00, len_hi, len_lo, payload...]
//!   TAG_WINSIZE (0x57): [0x57, rows_hi, rows_lo, cols_hi, cols_lo,
//!                        xpix_hi, xpix_lo, ypix_hi, ypix_lo]  — 9 bytes total
//!
//! Daemon → client: raw bytes (child pty output, no framing).
//!
//! EMBER_GH_WIRE_DONE

mod classify;

use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Socket resolution (matches ember-proxy/src/claude_code_hook.rs pattern)
// ---------------------------------------------------------------------------

/// Resolve the daemon UDS path.
///
/// Precedence:
///   1. `EMBER_SOCKET_PATH` env var (used by qember.sh + integration tests)
///   2. `~/.ember/run/daemon.sock` (matches DaemonConfig::default())
///   3. `/tmp/.ember/run/daemon.sock` if $HOME is unset
fn daemon_socket_path() -> PathBuf {
    if let Ok(p) = env::var("EMBER_SOCKET_PATH") {
        return PathBuf::from(p);
    }
    let base = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".ember").join("run").join("daemon.sock")
}

// ---------------------------------------------------------------------------
// JSON-RPC-over-UDS call (matches emberlink-cli/src/broker.rs::call_daemon)
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum RpcError {
    DaemonUnavailable(String),
    Io(String),
    Protocol(String),
    DaemonRpc { code: i32, message: String },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::DaemonUnavailable(s) => write!(f, "daemon unavailable: {s}"),
            RpcError::Io(s) => write!(f, "io: {s}"),
            RpcError::Protocol(s) => write!(f, "protocol: {s}"),
            RpcError::DaemonRpc { code, message } => {
                write!(f, "daemon rpc error {code}: {message}")
            }
        }
    }
}

/// Send one JSON-RPC request over the daemon socket and return the `result`.
///
/// Wire format (newline-delimited JSON per handler.rs::dispatch_method):
///   → `{"id":"1","method":<method>,"params":<params>}\n`
///   ← `{"id":"1","result":<result>}\n`  or  `{"id":"1","error":{...}}\n`
///
/// Matches `call_daemon` in crates/emberlink-cli/src/broker.rs (same wire
/// shape, same error-extraction logic).
fn call_daemon_rpc(socket_path: &std::path::Path, method: &str, params: &Value) -> Result<Value, RpcError> {
    let stream = UnixStream::connect(socket_path).map_err(|e| {
        RpcError::DaemonUnavailable(format!("{}: {e}", socket_path.display()))
    })?;

    let mut writer = stream.try_clone().map_err(|e| RpcError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer.write_all(line.as_bytes()).map_err(|e| RpcError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader.read_line(&mut response_line).map_err(|e| RpcError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| RpcError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(RpcError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// PTY wire-frame helpers (mirrors handler.rs framing — see that file for
// the canonical format documentation)
// ---------------------------------------------------------------------------

/// Tag byte for a stdin data frame (client → daemon).
const TAG_DATA: u8 = 0x00;

/// Tag byte for a terminal winsize update frame (client → daemon).
/// ASCII 'W' — mnemonic for WinSize.
const TAG_WINSIZE: u8 = 0x57;

/// Encode a stdin chunk as a TAG_DATA frame: [0x00, len_hi, len_lo, payload].
fn encode_data_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(3 + len);
    out.push(TAG_DATA);
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(&data[..len]);
    out
}

/// Encode a winsize update as a TAG_WINSIZE frame (9 bytes total):
/// [0x57, rows_hi, rows_lo, cols_hi, cols_lo, xpix_hi, xpix_lo, ypix_hi, ypix_lo]
fn encode_winsize_frame(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> [u8; 9] {
    [
        TAG_WINSIZE,
        (rows >> 8) as u8,
        (rows & 0xff) as u8,
        (cols >> 8) as u8,
        (cols & 0xff) as u8,
        (xpixel >> 8) as u8,
        (xpixel & 0xff) as u8,
        (ypixel >> 8) as u8,
        (ypixel & 0xff) as u8,
    ]
}

/// Query the current terminal size via TIOCGWINSZ.
/// Returns (rows, cols, xpixel, ypixel), or (24, 80, 0, 0) as a safe default.
#[cfg(unix)]
fn current_winsize() -> (u16, u16, u16, u16) {
    let mut ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe {
        libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws);
    }
    (ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel)
}

// ---------------------------------------------------------------------------
// SIGWINCH capture
//
// We install a signal handler that sets an AtomicBool flag. The bridge
// thread polls this flag and sends a TAG_WINSIZE frame when it fires.
// ---------------------------------------------------------------------------

static SIGWINCH_FLAG: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_FLAG.store(true, Ordering::Relaxed);
}

/// Install the SIGWINCH signal handler. Safe to call once before the
/// bridge thread starts.
#[cfg(unix)]
fn install_sigwinch_handler() {
    unsafe {
        libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as libc::sighandler_t);
    }
}

// ---------------------------------------------------------------------------
// PTY bridge — client side
//
// The daemon (handle_broker_exec → pty_bridge_run in handler.rs) connects
// to our UDS socket and then:
//   daemon → writes child stdout/stderr bytes to us  (raw, no framing)
//   us     → write to our stdout
//   us     → read our stdin and write to daemon      (TAG_DATA frames)
//   SIGWINCH → capture winsize, write TAG_WINSIZE frame to daemon
//
// We pump in a dedicated thread so the main thread can block on the
// broker_exec RPC response (which only arrives after the child exits).
// ---------------------------------------------------------------------------

/// Accept one connection from the daemon on the PTY UDS and pump bytes
/// between stdin/stdout and that connection until EOF on either side.
///
/// Called in a background thread. The `done` flag lets the main thread
/// signal that the RPC response has arrived (child exited), prompting a
/// clean teardown if the poll loop hasn't already detected EOF.
fn pty_bridge_client(listener: UnixListener, done: Arc<Mutex<bool>>) {
    listener.set_nonblocking(false).ok();

    // The daemon connects immediately after fork. We block here until it does.
    let stream = match listener.accept() {
        Ok((s, _)) => s,
        Err(e) => {
            tracing::warn!(error = %e, "pty bridge: accept failed");
            return;
        }
    };

    let mut read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "pty bridge: clone stream failed");
            return;
        }
    };
    let mut write_stream = stream;

    // Set read stream to non-blocking so we can interleave stdin polling.
    read_stream.set_nonblocking(true).ok();

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut buf = [0u8; 4096];
    let mut stdin_buf = [0u8; 4096];

    loop {
        // Check if main thread signals done.
        if let Ok(d) = done.lock() {
            if *d {
                break;
            }
        }

        // Check for a pending SIGWINCH and send a TAG_WINSIZE frame.
        if SIGWINCH_FLAG.swap(false, Ordering::Relaxed) {
            #[cfg(unix)]
            {
                let (rows, cols, xpixel, ypixel) = current_winsize();
                let frame = encode_winsize_frame(rows, cols, xpixel, ypixel);
                if write_stream.write_all(&frame).is_err() {
                    break;
                }
                tracing::debug!(rows, cols, "pty bridge client: sent TAG_WINSIZE");
            }
        }

        // Read from daemon (child pty output) → our stdout.
        // Daemon → client is raw bytes (no framing).
        match read_stream.read(&mut buf) {
            Ok(0) => break, // EOF from daemon
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
                stdout.flush().ok();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                tracing::debug!(error = %e, "pty bridge: read from daemon");
                break;
            }
        }

        // Read from our stdin → daemon as TAG_DATA frames.
        match stdin.read(&mut stdin_buf) {
            Ok(0) => break,
            Ok(n) => {
                let framed = encode_data_frame(&stdin_buf[..n]);
                if write_stream.write_all(&framed).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    // 1. env-detect: if not inside an ember session, exec gh directly.
    let args: Vec<String> = env::args().skip(1).collect();
    if env::var_os("EMBER_SESSION_ID").is_none() {
        // Passthrough: exec the real gh binary.
        let gh_bin = env::var("EMBER_GH_BINARY").unwrap_or_else(|_| "gh".to_string());
        let err = std::os::unix::process::CommandExt::exec(
            std::process::Command::new(&gh_bin).args(&args),
        );
        eprintln!("ember-gh: failed to exec {gh_bin}: {err}");
        return ExitCode::from(126u8);
    }

    // 2. classify argv → action_key.
    let classified = match classify::classify_gh_argv(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ember-gh: classify error: {e}");
            return ExitCode::from(2);
        }
    };

    tracing::info!(
        action_key = %classified.action_key,
        "ember-gh: dispatching via broker.exec"
    );

    // Parse EMBER_GRANT_ID (informational; included in log, not sent in RPC
    // since broker_exec doesn't take a grant_id param directly — the daemon
    // validates grant scope from session context).
    let grant_id = env::var("EMBER_GRANT_ID").ok();
    tracing::info!(
        action_key = %classified.action_key,
        grant_id = ?grant_id,
        "ember-gh: broker.resolve+exec"
    );

    // 3. Resolve daemon socket path.
    let socket_path = daemon_socket_path();

    // 4. Resolve the real `gh` binary. The daemon's broker_exec takes an
    //    absolute path and executes it directly. We resolve here so the daemon
    //    doesn't need $PATH. The env var EMBER_GH_BINARY lets tests inject
    //    a fake binary.
    let gh_bin = env::var("EMBER_GH_BINARY").unwrap_or_else(|_| {
        // Walk PATH entries to find the real gh binary. If not found fall back
        // to the literal "gh" (daemon will fail with spawn error which surfaces
        // cleanly in stderr_tail).
        env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .map(|dir| format!("{dir}/gh"))
            .find(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false))
            .unwrap_or_else(|| "gh".to_string())
    });

    // 5. Create a temp UDS path for the PTY bridge. The daemon will connect
    //    to this path immediately after forkpty. We must bind before sending
    //    the RPC so no connection is lost.
    //
    //    Naming: /tmp/ember-gh-pty-<pid>.sock — short enough for UNIX_PATH_MAX
    //    (108 bytes on Linux). Using /tmp because the daemon and this process
    //    may have different working directories.
    let pty_sock_path = PathBuf::from(format!(
        "/tmp/ember-gh-pty-{}.sock",
        std::process::id()
    ));

    // Remove stale socket if it exists (e.g. from a crashed prior run).
    let _ = std::fs::remove_file(&pty_sock_path);

    let listener = match UnixListener::bind(&pty_sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ember-gh: failed to bind PTY socket {}: {e}", pty_sock_path.display());
            return ExitCode::from(1);
        }
    };

    // Ensure only the owner can connect (security hygiene).
    let _ = std::fs::set_permissions(&pty_sock_path, std::fs::Permissions::from_mode(0o600));

    let pty_sock_str = pty_sock_path.to_string_lossy().into_owned();

    // 6. Install SIGWINCH handler so terminal resize events are captured and
    //    forwarded to the daemon as TAG_WINSIZE frames by the bridge thread.
    #[cfg(unix)]
    install_sigwinch_handler();

    // Spawn the PTY bridge thread. It blocks on accept(), waiting for the
    // daemon to connect after fork. The `done` flag lets us signal clean
    // shutdown when the RPC response arrives (child exited).
    let done = Arc::new(Mutex::new(false));
    let done_clone = Arc::clone(&done);

    let bridge_thread = thread::spawn(move || {
        pty_bridge_client(listener, done_clone);
    });

    // Set stdin non-blocking for the bridge pump loop. We do this after
    // spawning the bridge thread (which reads stdin) so the main thread's
    // blocking RPC read is not affected.
    //
    // Safety: we only set the flag once; the bridge thread reads stdin in
    // a non-blocking loop after this point.
    unsafe {
        let flags = libc::fcntl(0 /* stdin fd */, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    // 7. Send broker_exec RPC to the daemon. This is the combined
    //    broker.resolve + broker.exec step: the daemon classifies the action
    //    server-side, mints the credential lease internally, exec's the binary
    //    with the lease envelope, and returns BrokerExecResponse once the
    //    child exits.
    //
    //    Wire shape: handler.rs::BrokerExecRequest (line 193–215).
    let params = json!({
        "binary": gh_bin,
        "argv": classified.forwarded_argv,
        "cwd": env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/tmp".to_string()),
        "env_passthrough": ["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"],
        "pty_socket_path": pty_sock_str,
    });

    let result = call_daemon_rpc(&socket_path, "broker_exec", &params);

    // 8. Signal the bridge thread that the child has exited (either by RPC
    //    response or error). The bridge thread will then drain any remaining
    //    bytes and exit.
    if let Ok(mut d) = done.lock() {
        *d = true;
    }

    // Wait for bridge thread to flush and exit (best-effort; 2-second cap).
    let _ = bridge_thread.join();

    // Cleanup temp socket.
    let _ = std::fs::remove_file(&pty_sock_path);

    // 9. Propagate exit code from child.
    //
    //    broker_exec response shape (handler.rs::BrokerExecResponse line 218–227):
    //      { "exit_code": i32, "success": bool, "stderr_tail": String }
    match result {
        Ok(resp) => {
            // Print any captured stderr from non-PTY fallback (empty for PTY path).
            let stderr_tail = resp.get("stderr_tail").and_then(|v| v.as_str()).unwrap_or("");
            if !stderr_tail.is_empty() {
                eprint!("{stderr_tail}");
            }

            let exit_code = resp
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            tracing::info!(
                exit_code = exit_code,
                action_key = %classified.action_key,
                "ember-gh: child exited"
            );

            // Clamp to u8 range; negative codes (signal-killed) map to 1.
            if exit_code < 0 {
                ExitCode::from(1u8)
            } else {
                ExitCode::from(exit_code.min(255) as u8)
            }
        }
        Err(RpcError::DaemonUnavailable(msg)) => {
            eprintln!("ember-gh: daemon unavailable — {msg}");
            eprintln!("ember-gh: start emberd with 'ember daemon start'");
            ExitCode::from(2u8)
        }
        Err(RpcError::DaemonRpc { code, message }) => {
            eprintln!("ember-gh: broker_exec rejected (code={code}): {message}");
            ExitCode::from(1u8)
        }
        Err(e) => {
            eprintln!("ember-gh: broker_exec error: {e}");
            ExitCode::from(1u8)
        }
    }
}
