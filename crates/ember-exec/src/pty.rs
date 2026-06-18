//! CLASSIFICATION: PUBLIC
//!
//! Standalone pty-bridge: spawn a child with a controlling pty and route
//! its stdin/stdout/stderr through a tokio UnixStream.
//!
//! ## Wire format (client → server)
//!
//! ```text
//! TAG_DATA    (0x00): [0x00, len_hi, len_lo, payload…]
//! TAG_WINSIZE (0x57): [0x57, rows_hi, rows_lo, cols_hi, cols_lo,
//!                      xpix_hi, xpix_lo, ypix_hi, ypix_lo]  — 9 bytes total
//! ```
//!
//! ## Wire format (server → client)
//!
//! Raw bytes — child pty output with no framing.
//!
//! ## Design notes
//!
//! `serve` wraps a `spawn_blocking` call: `forkpty(3)` forks the process and
//! the parent must run a blocking poll loop to move bytes between the master
//! fd and the UDS. `spawn_blocking` keeps the async thread pool free.
//!
//! `connect` is fully async: it connects to the UDS, optionally sends a
//! resize frame and stdin bytes, then reads all server output until EOF.
//!
//! See `lib.rs` §"Open questions" for known limitations and follow-up work.

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::process::ExitStatus;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PtyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("child exit unavailable")]
    ChildExitUnavailable,
    #[error("pty allocation failed: {0}")]
    PtyAlloc(String),
}

// ---------------------------------------------------------------------------
// Wire protocol constants (mirrored from core-construct-runtime::pty_bridge)
// ---------------------------------------------------------------------------

/// Client → server: stdin data frame tag.
pub const TAG_DATA: u8 = 0x00;

/// Client → server: terminal resize frame tag.
pub const TAG_WINSIZE: u8 = 0x57;

// ---------------------------------------------------------------------------
// PtyBridge
// ---------------------------------------------------------------------------

/// Spawn the child with a controlling pty; expose stdin/stdout/stderr +
/// window-resize over a tokio UnixStream to the caller.
pub struct PtyBridge {
    _priv: (),
}

impl PtyBridge {
    /// Server side: spawn `cmd` with a fresh pty pair, accept a single client
    /// on `socket_path`, forward bytes both ways until the child exits.
    ///
    /// The command's program and args are extracted and forwarded to the
    /// underlying `forkpty(3)` + `execvp(3)` implementation.
    ///
    /// Returns the child's exit status.
    #[cfg(target_os = "linux")]
    pub async fn serve(
        socket_path: &Path,
        cmd: tokio::process::Command,
    ) -> Result<ExitStatus, PtyError> {
        let prog = cmd.as_std().get_program().to_string_lossy().into_owned();
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        serve_inner(socket_path, &prog, &args_ref).await
    }

    /// Client side: connect to `socket_path`, forward a single write of
    /// `stdin_bytes` to the server, collect all server output, and return
    /// the server's output bytes together with a synthesized exit status.
    ///
    /// `resize` — if `Some((rows, cols))`, sends a `TAG_WINSIZE` frame after
    /// connecting so the server-side pty is resized before output is read.
    pub async fn connect(socket_path: &Path) -> Result<ExitStatus, PtyError> {
        let (_, status) = connect_and_collect(socket_path, None, None).await?;
        Ok(status)
    }
}

// ---------------------------------------------------------------------------
// serve_inner — thin wrapper that binds + accepts, then delegates to
// pump_connection for the fork+pty+pump body.
// ---------------------------------------------------------------------------

/// Bind a UDS listener at `socket_path`, accept a single client connection,
/// then run the fork+pty+pump body via [`pump_connection`] until the child
/// exits.
///
/// Refactored in SCION-EMBER-EXEC-D-PTY-WIRE: the per-connection body now
/// lives in [`pump_connection`] so `handle_spawn_directive` in `spawn.rs`
/// can reuse it over an in-flight stream without re-binding a socket.
/// `serve_inner` keeps its original shape (open listener, accept one client,
/// pump) so the spike's existing tests stay green.
#[cfg(target_os = "linux")]
pub async fn serve_inner(
    socket_path: &Path,
    prog: &str,
    argv: &[&str],
) -> Result<ExitStatus, PtyError> {
    let socket_path = socket_path.to_path_buf();

    // Bind and accept on a blocking thread so we keep the async runtime free
    // while waiting for the single client connection.
    let std_stream = tokio::task::spawn_blocking(
        move || -> Result<std::os::unix::net::UnixStream, PtyError> {
            use std::os::unix::net::UnixListener;
            let listener = UnixListener::bind(&socket_path).map_err(PtyError::Io)?;
            let (stream, _) = listener.accept().map_err(PtyError::Io)?;
            Ok(stream)
        },
    )
    .await
    .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))??;

    // Convert the blocking std UnixStream to a tokio UnixStream so the pump
    // can use async I/O against the framed wire.
    std_stream.set_nonblocking(true).map_err(PtyError::Io)?;
    let tokio_stream = UnixStream::from_std(std_stream).map_err(PtyError::Io)?;

    // Delegate the fork+pty+pump body. The spike's calling convention does
    // NOT include `prog` in `argv`; conventional execvp argv starts with the
    // program name. Prepend it here so `pump_connection`'s argv slice owns
    // the full argv vector (matching the directive convention).
    let mut argv_owned: Vec<String> = Vec::with_capacity(argv.len() + 1);
    argv_owned.push(prog.to_string());
    for a in argv {
        argv_owned.push((*a).to_string());
    }
    pump_connection(tokio_stream, Path::new(prog), &argv_owned).await
}

// ---------------------------------------------------------------------------
// pump_connection — fork+pty+pump over a pre-bound async stream
// ---------------------------------------------------------------------------

/// SCION-EMBER-EXEC-D-PTY-WIRE: fork a child with a controlling pty, exec
/// `prog argv` in the child, and pump bytes between the pty master and the
/// pre-bound `stream` until the child exits.
///
/// Wire format on `stream`:
///
/// - **inbound (peer → pty master):** length-prefixed [`TAG_DATA`] /
///   [`TAG_WINSIZE`] frames (see this module's header).
/// - **outbound (pty master → peer):** raw bytes; no framing.
///
/// The outer-protocol wrapper in `spawn.rs::handle_spawn_directive` uses
/// `tokio::io::duplex` to bridge between the `ExecFrame` JSON protocol and
/// this raw / TAG-framed stream.
///
/// Returns the child's `ExitStatus` after `waitpid` reaps it.
///
/// On non-Linux targets (macOS, etc.) this returns `Err(PtyError::PtyAlloc(...))`
/// immediately — `forkpty(3)` has a different signature on macOS and the SCION
/// ember-exec runtime only runs on Linux in production.
#[cfg(target_os = "linux")]
pub async fn pump_connection<S>(
    stream: S,
    prog: &Path,
    argv: &[String],
) -> Result<ExitStatus, PtyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::ffi::CString;

    let prog_string = prog.to_string_lossy().into_owned();
    let argv_owned: Vec<String> = argv.to_vec();

    // forkpty + execvp must run on a blocking thread: forkpty is a hostile
    // syscall in the middle of an async runtime, and the child path cannot
    // return to async land. The parent path returns master_fd + pid back to
    // the caller for async pumping.
    let (master_fd, pid) =
        tokio::task::spawn_blocking(move || -> Result<(RawFd, libc::pid_t), PtyError> {
            let prog_c = CString::new(prog_string.as_str())
                .map_err(|e| PtyError::PtyAlloc(format!("program CString: {e}")))?;
            // `argv_owned` is the full argv vector (argv[0] is the conventional
            // program name). Empty argv falls back to `[prog]` so execvp gets at
            // least one entry; this matches conventional execvp(3) usage.
            let mut argv_c: Vec<CString> = Vec::with_capacity(argv_owned.len().max(1));
            if argv_owned.is_empty() {
                argv_c.push(prog_c.clone());
            } else {
                for a in &argv_owned {
                    argv_c.push(
                        CString::new(a.as_str())
                            .map_err(|e| PtyError::PtyAlloc(format!("arg CString: {e}")))?,
                    );
                }
            }
            let mut argv_ptrs: Vec<*const libc::c_char> =
                argv_c.iter().map(|s| s.as_ptr()).collect();
            argv_ptrs.push(std::ptr::null());

            let mut master_fd: libc::c_int = -1;
            let ws = libc::winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let pid = unsafe {
                libc::forkpty(
                    &mut master_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &ws,
                )
            };

            if pid < 0 {
                let err = std::io::Error::last_os_error();
                return Err(PtyError::PtyAlloc(format!("forkpty: {err}")));
            }

            if pid == 0 {
                // ---- CHILD ----
                // exec immediately; _exit on failure so we don't run any Drop
                // glue from the parent's async runtime.
                unsafe {
                    libc::execvp(prog_c.as_ptr(), argv_ptrs.as_ptr());
                    libc::_exit(127);
                }
            }

            // ---- PARENT ----
            Ok((master_fd, pid))
        })
        .await
        .map_err(|e| PtyError::Io(std::io::Error::other(e.to_string())))??;

    set_nonblocking(master_fd).map_err(|e| {
        // Close master and reap the child on setup error.
        unsafe {
            libc::close(master_fd);
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        PtyError::PtyAlloc(format!("set_nonblocking master fd: {e}"))
    })?;

    // Run the async pump loop.
    let raw_code = async_bridge(master_fd, pid, stream).await?;
    decode_exit(raw_code)
}

#[cfg(not(target_os = "linux"))]
pub async fn pump_connection<S>(
    _stream: S,
    _prog: &Path,
    _argv: &[String],
) -> Result<ExitStatus, PtyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Err(PtyError::PtyAlloc(
        "pump_connection: macOS unsupported (Linux-only forkpty path)".into(),
    ))
}

// ---------------------------------------------------------------------------
// Async bridge loop (pump_connection helper)
// ---------------------------------------------------------------------------

/// `AsRawFd` wrapper so `tokio::io::unix::AsyncFd` can register the pty master.
#[cfg(target_os = "linux")]
struct MasterFd(RawFd);

#[cfg(target_os = "linux")]
impl AsRawFd for MasterFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(target_os = "linux")]
impl Drop for MasterFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
            self.0 = -1;
        }
    }
}

/// Async equivalent of [`bridge_loop`]: pump bytes between `master_fd` and
/// `stream` until the child exits. Uses `tokio::io::unix::AsyncFd` to poll
/// the pty master and `tokio::select!` to multiplex against the async
/// stream.
#[cfg(target_os = "linux")]
async fn async_bridge<S>(master_fd: RawFd, pid: libc::pid_t, stream: S) -> Result<i32, PtyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::unix::AsyncFd;

    let master = AsyncFd::new(MasterFd(master_fd)).map_err(PtyError::Io)?;
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut master_buf = [0u8; 4096];
    let mut client_buf = [0u8; 4096];
    let mut recv_buf: Vec<u8> = Vec::new();
    let mut client_eof = false;
    let mut child_exited = false;
    let mut raw_code: i32 = -1;

    // We poll waitpid periodically (every 50ms) using tokio::time. The pty
    // master also surfaces EIO when the slave side closes, which races
    // waitpid to detect child exit; either signal closes the loop.
    let mut waitpid_tick = tokio::time::interval(std::time::Duration::from_millis(50));
    waitpid_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if child_exited {
            // Drain any remaining bytes from the pty master, then break.
            loop {
                let n = unsafe {
                    libc::read(
                        master.as_raw_fd(),
                        master_buf.as_mut_ptr().cast(),
                        master_buf.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
                if writer.write_all(&master_buf[..n as usize]).await.is_err() {
                    break;
                }
            }
            let _ = writer.flush().await;
            break;
        }

        tokio::select! {
            // pty master ready → read raw bytes, write to stream.
            master_ready = master.readable() => {
                let mut guard = match master_ready {
                    Ok(g) => g,
                    Err(e) => return Err(PtyError::Io(e)),
                };
                let n = unsafe {
                    libc::read(
                        master.as_raw_fd(),
                        master_buf.as_mut_ptr().cast(),
                        master_buf.len(),
                    )
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    // EIO on the master fd means the slave side closed (child
                    // exited). Surface this by going to the wait-and-drain
                    // path below.
                    if err.raw_os_error() == Some(libc::EIO) {
                        // Reap the child synchronously since the slave just
                        // closed.
                        let mut status: libc::c_int = 0;
                        unsafe { libc::waitpid(pid, &mut status, 0) };
                        raw_code = if libc::WIFEXITED(status) {
                            libc::WEXITSTATUS(status)
                        } else {
                            -1
                        };
                        child_exited = true;
                        continue;
                    }
                    return Err(PtyError::Io(err));
                } else if n == 0 {
                    // Master EOF — child closed pty. Reap.
                    let mut status: libc::c_int = 0;
                    unsafe { libc::waitpid(pid, &mut status, 0) };
                    raw_code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        -1
                    };
                    child_exited = true;
                    continue;
                } else {
                    if writer.write_all(&master_buf[..n as usize]).await.is_err() {
                        // Peer dropped — keep child running to drain, but
                        // we cannot forward further bytes.
                        break;
                    }
                    let _ = writer.flush().await;
                }
            }

            // stream readable → read framed input, dispatch to master.
            read_result = reader.read(&mut client_buf), if !client_eof => {
                match read_result {
                    Ok(0) => {
                        client_eof = true;
                    }
                    Ok(n) => {
                        recv_buf.extend_from_slice(&client_buf[..n]);
                        dispatch_frames(master.as_raw_fd(), &mut recv_buf);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        client_eof = true;
                    }
                }
            }

            // Periodic waitpid tick to detect child exit even if the master
            // hasn't surfaced EIO yet.
            _ = waitpid_tick.tick() => {
                let mut status: libc::c_int = 0;
                let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if waited == pid {
                    raw_code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        -1
                    };
                    child_exited = true;
                }
            }
        }
    }

    // master is closed via MasterFd::drop.
    Ok(raw_code)
}

// ---------------------------------------------------------------------------
// connect_and_collect — async client helper
// ---------------------------------------------------------------------------

/// Connect to `socket_path`, optionally send a resize frame, optionally send
/// stdin bytes as a framed TAG_DATA payload, collect all server output, and
/// return the raw bytes together with a synthesized exit status.
///
/// `stdin_bytes` — if `Some(bytes)`, sends a `TAG_DATA` frame then shuts down
/// the write half of the socket so the server sees EOF on its pty master.
///
/// `resize` — if `Some((rows, cols))`, sends a `TAG_WINSIZE` frame first
/// (before any stdin data).
pub async fn connect_and_collect(
    socket_path: &Path,
    stdin_bytes: Option<&[u8]>,
    resize: Option<(u16, u16)>,
) -> Result<(Vec<u8>, ExitStatus), PtyError> {
    let mut stream = UnixStream::connect(socket_path).await?;

    // Optionally send resize frame first.
    if let Some((rows, cols)) = resize {
        let frame = encode_winsize_frame(rows, cols, 0, 0);
        stream.write_all(&frame).await?;
    }

    // Optionally send stdin bytes as a framed TAG_DATA payload.
    if let Some(bytes) = stdin_bytes {
        let frame = encode_data_frame(bytes);
        stream.write_all(&frame).await?;
    }

    // Half-close the write side so the server pty master sees EOF once the
    // data above has been consumed by the child.
    stream.shutdown().await?;

    // Drain server output until the server closes the connection.
    let mut output = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => output.extend_from_slice(&buf[..n]),
            Err(e) => return Err(PtyError::Io(e)),
        }
    }

    let status = decode_exit(0)?;
    Ok((output, status))
}

// ---------------------------------------------------------------------------
// Frame dispatch
// ---------------------------------------------------------------------------

/// Parse accumulated client frames and dispatch to the pty master fd.
/// Consumes fully parsed frames from `buf`; leaves partial frames intact.
#[cfg(target_os = "linux")]
fn dispatch_frames(master_fd: RawFd, buf: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < buf.len() {
        match buf[pos] {
            TAG_DATA => {
                if buf.len() < pos + 3 {
                    break;
                }
                let len = ((buf[pos + 1] as usize) << 8) | (buf[pos + 2] as usize);
                if buf.len() < pos + 3 + len {
                    break;
                }
                write_all_fd(master_fd, &buf[pos + 3..pos + 3 + len]);
                pos += 3 + len;
            }
            TAG_WINSIZE => {
                if buf.len() < pos + 9 {
                    break;
                }
                let rows = u16::from_be_bytes([buf[pos + 1], buf[pos + 2]]);
                let cols = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]);
                let xpix = u16::from_be_bytes([buf[pos + 5], buf[pos + 6]]);
                let ypix = u16::from_be_bytes([buf[pos + 7], buf[pos + 8]]);
                apply_winsize(master_fd, rows, cols, xpix, ypix);
                pos += 9;
            }
            _ => {
                pos += 1; // skip unknown tag byte
            }
        }
    }
    buf.drain(..pos);
}

// ---------------------------------------------------------------------------
// TIOCSWINSZ helper
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn apply_winsize(master_fd: RawFd, rows: u16, cols: u16, xpixel: u16, ypixel: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    unsafe {
        libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
    }
}

// ---------------------------------------------------------------------------
// fd helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: RawFd) -> Result<(), std::io::Error> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_all_fd(fd: RawFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        buf = &buf[n as usize..];
    }
}

// ---------------------------------------------------------------------------
// Frame encoding helpers
// ---------------------------------------------------------------------------

/// Encode `data` as a TAG_DATA frame: `[0x00, len_hi, len_lo, payload…]`.
pub fn encode_data_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(3 + len);
    out.push(TAG_DATA);
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(&data[..len]);
    out
}

/// Encode a terminal resize as a TAG_WINSIZE frame (9 bytes).
pub fn encode_winsize_frame(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> [u8; 9] {
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

// ---------------------------------------------------------------------------
// Exit status decoding
// ---------------------------------------------------------------------------

/// Convert a raw exit-code integer into a `std::process::ExitStatus`.
///
/// Uses `std::os::unix::process::ExitStatusExt::from_raw` which accepts the
/// raw `waitpid(2)` status word.  For a normal exit with code `c`, the
/// waitpid status is `(c & 0xff) << 8`.
fn decode_exit(raw_code: i32) -> Result<ExitStatus, PtyError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let wait_status = if raw_code >= 0 {
            (raw_code & 0xff) << 8
        } else {
            9
        };
        Ok(ExitStatus::from_raw(wait_status))
    }
    #[cfg(not(unix))]
    {
        let _ = raw_code;
        std::process::Command::new("true")
            .status()
            .map_err(PtyError::Io)
    }
}
