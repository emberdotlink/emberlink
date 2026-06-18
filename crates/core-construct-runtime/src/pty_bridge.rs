//! Client-side PTY bridge: pumps bytes between stdin/stdout and the daemon's
//! PTY UDS connection until EOF on either side.
//!
//! ## Wire format (client → daemon)
//!
//!   TAG_DATA   (0x00): [0x00, len_hi, len_lo, payload...]
//!   TAG_WINSIZE (0x57): [0x57, rows_hi, rows_lo, cols_hi, cols_lo,
//!                        xpix_hi, xpix_lo, ypix_hi, ypix_lo]  — 9 bytes total
//!   TAG_SIGINT  (0x49): [0x49]  — single byte, no payload
//!   TAG_SIGTERM (0x4A): [0x4A]
//!   TAG_SIGTSTP (0x4B): [0x4B]
//!   TAG_SIGCONT (0x4C): [0x4C]
//!
//! Daemon → client: raw bytes (child pty output, no framing).

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Tag byte for a stdin data frame (client → daemon).
pub const TAG_DATA: u8 = 0x00;

/// Tag byte for a terminal winsize update frame (client → daemon).
/// ASCII 'W' — mnemonic for WinSize.
pub const TAG_WINSIZE: u8 = 0x57;

/// Signal-forwarding control frames (single-byte, no payload).
/// Byte values MUST agree with handler.rs (the daemon-side decoder).
pub const TAG_SIGINT: u8 = 0x49;
pub const TAG_SIGTERM: u8 = 0x4A;
pub const TAG_SIGTSTP: u8 = 0x4B;
pub const TAG_SIGCONT: u8 = 0x4C;

/// Encode a stdin chunk as a TAG_DATA frame: [0x00, len_hi, len_lo, payload].
pub fn encode_data_frame(data: &[u8]) -> Vec<u8> {
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

/// Query the current terminal size via TIOCGWINSZ.
/// Returns (rows, cols, xpixel, ypixel), or (24, 80, 0, 0) as a safe default.
#[cfg(unix)]
pub fn current_winsize() -> (u16, u16, u16, u16) {
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws);
    }
    (ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel)
}

// ---------------------------------------------------------------------------
// SIGWINCH + signal-forwarding flags
// ---------------------------------------------------------------------------

pub static SIGWINCH_FLAG: AtomicBool = AtomicBool::new(false);
pub static SIGINT_FLAG: AtomicBool = AtomicBool::new(false);
pub static SIGTERM_FLAG: AtomicBool = AtomicBool::new(false);
pub static SIGTSTP_FLAG: AtomicBool = AtomicBool::new(false);
pub static SIGCONT_FLAG: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_FLAG.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
extern "C" fn sigint_handler(_sig: libc::c_int) {
    SIGINT_FLAG.store(true, Ordering::Relaxed);
}
#[cfg(unix)]
extern "C" fn sigterm_handler(_sig: libc::c_int) {
    SIGTERM_FLAG.store(true, Ordering::Relaxed);
}
#[cfg(unix)]
extern "C" fn sigtstp_handler(_sig: libc::c_int) {
    SIGTSTP_FLAG.store(true, Ordering::Relaxed);
}
#[cfg(unix)]
extern "C" fn sigcont_handler(_sig: libc::c_int) {
    SIGCONT_FLAG.store(true, Ordering::Relaxed);
}

/// Install SIGWINCH + signal-forwarding handlers.
/// Safe to call once before the bridge thread starts.
#[cfg(unix)]
pub fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGWINCH,
            sigwinch_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            sigterm_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTSTP,
            sigtstp_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGCONT,
            sigcont_handler as *const () as libc::sighandler_t,
        );
    }
}

// ---------------------------------------------------------------------------
// PTY bridge client — runs in a background thread
// ---------------------------------------------------------------------------

/// Accept one connection from the daemon on the PTY UDS and pump bytes
/// between stdin/stdout and that connection until EOF on either side.
///
/// Called in a background thread. The `done` flag lets the main thread
/// signal that the RPC response has arrived (child exited), prompting a
/// clean teardown if the poll loop hasn't already detected EOF.
pub fn pty_bridge_client(listener: UnixListener, done: Arc<Mutex<bool>>) {
    listener.set_nonblocking(true).ok();

    let stream = loop {
        if let Ok(d) = done.lock()
            && *d
        {
            return;
        }
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                tracing::warn!(error = %e, "pty bridge: accept failed");
                return;
            }
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

    read_stream.set_nonblocking(true).ok();
    let stream_fd = read_stream.as_raw_fd();

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let stdin_fd = stdin.as_raw_fd();

    let mut buf = [0u8; 4096];
    let mut stdin_buf = [0u8; 4096];

    // Once stdin EOFs we stop polling it, but the daemon→stdout half of
    // the bridge must keep pumping until either the daemon closes its
    // end (child exited) or the main thread sets `done = true` after
    // the broker_exec RPC reply lands. Treating stdin EOF as bridge
    // teardown caused `BridgeExit::ShimDisappeared` → SIGTERM cascade
    // on every non-interactive shim invocation (autopilot scripts run
    // shims with stdin=/dev/null), killing the credential-injected
    // child mid-flight. See META-BROKER-EXEC-STDIN-EOF-SHIM-RACE.
    let mut stdin_eof = false;

    loop {
        if let Ok(d) = done.lock()
            && *d
        {
            // The daemon only replies after the child has exited, but the UDS
            // can still have unread child output buffered locally. Drain once
            // before teardown so fast-failing tools don't lose their final
            // auth/error text when the main thread flips `done = true`.
            if let Err(e) = drain_daemon_output(&mut read_stream, &mut stdout, &mut buf) {
                tracing::debug!(error = %e, "pty bridge: drain on done");
            }
            break;
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
                tracing::debug!(rows, cols, "pty bridge: sent TAG_WINSIZE");
            }
        }

        // Check for pending forwarded signals and send single-byte TAG_SIG* frames.
        #[cfg(unix)]
        {
            if SIGINT_FLAG.swap(false, Ordering::Relaxed)
                && write_stream.write_all(&[TAG_SIGINT]).is_err()
            {
                break;
            }
            if SIGTERM_FLAG.swap(false, Ordering::Relaxed)
                && write_stream.write_all(&[TAG_SIGTERM]).is_err()
            {
                break;
            }
            if SIGTSTP_FLAG.swap(false, Ordering::Relaxed)
                && write_stream.write_all(&[TAG_SIGTSTP]).is_err()
            {
                break;
            }
            if SIGCONT_FLAG.swap(false, Ordering::Relaxed)
                && write_stream.write_all(&[TAG_SIGCONT]).is_err()
            {
                break;
            }
        }

        // Wait for activity on either fd, with a 100ms timeout so the
        // `done` flag and signal flags get re-checked promptly. Without
        // this throttle, the loop busy-spins after stdin EOF because
        // both reads return WouldBlock immediately.
        #[cfg(unix)]
        {
            let stdin_events = if stdin_eof { 0 } else { libc::POLLIN };
            let mut fds = [
                libc::pollfd {
                    fd: stream_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stdin_fd,
                    events: stdin_events,
                    revents: 0,
                },
            ];
            let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            if r < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::debug!(error = %err, "pty bridge: poll");
                break;
            }
        }

        // Read from daemon (child pty output) → our stdout.
        match drain_daemon_output(&mut read_stream, &mut stdout, &mut buf) {
            Ok(DaemonOutputDrain::Eof) => break,
            Ok(DaemonOutputDrain::WouldBlock) => {}
            Err(e) => {
                tracing::debug!(error = %e, "pty bridge: read from daemon");
                break;
            }
        }

        // Read from our stdin → daemon as TAG_DATA frames. Once stdin
        // EOFs (or errors), stop polling it but keep the bridge alive
        // for the daemon→stdout direction.
        if !stdin_eof {
            match pump_stdin_once(&mut stdin, &mut stdin_buf, &mut write_stream) {
                PumpStdin::Continue => {}
                PumpStdin::Eof => stdin_eof = true,
                PumpStdin::WriteError => break,
            }
        }
    }
}

enum DaemonOutputDrain {
    WouldBlock,
    Eof,
}

fn drain_daemon_output<R: Read, W: Write>(
    read_stream: &mut R,
    stdout: &mut W,
    buf: &mut [u8],
) -> io::Result<DaemonOutputDrain> {
    let mut wrote_any = false;
    loop {
        match read_stream.read(buf) {
            Ok(0) => {
                if wrote_any {
                    stdout.flush()?;
                }
                return Ok(DaemonOutputDrain::Eof);
            }
            Ok(n) => {
                stdout.write_all(&buf[..n])?;
                wrote_any = true;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if wrote_any {
                    stdout.flush()?;
                }
                return Ok(DaemonOutputDrain::WouldBlock);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Outcome of a single stdin → daemon read+forward attempt.
///
/// Distinguishes "stdin is EOF, but the bridge should keep pumping the
/// daemon→stdout direction" from "the daemon stream is unwriteable, so
/// the bridge must tear down." The previous implementation collapsed
/// these into a single `break`, which surfaced to the daemon as
/// `BridgeExit::ShimDisappeared` and triggered the SIGTERM cascade on
/// non-interactive shim invocations (regression covered by tests below).
enum PumpStdin {
    Continue,
    Eof,
    WriteError,
}

fn pump_stdin_once<R: Read, W: Write>(
    stdin: &mut R,
    stdin_buf: &mut [u8],
    write_stream: &mut W,
) -> PumpStdin {
    match stdin.read(stdin_buf) {
        Ok(0) => PumpStdin::Eof,
        Ok(n) => {
            let framed = encode_data_frame(&stdin_buf[..n]);
            if write_stream.write_all(&framed).is_err() {
                PumpStdin::WriteError
            } else {
                PumpStdin::Continue
            }
        }
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => PumpStdin::Continue,
        Err(_) => PumpStdin::Eof,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::{collections::VecDeque, io};

    /// Regression for META-BROKER-EXEC-STDIN-EOF-SHIM-RACE.
    ///
    /// When stdin returns `Ok(0)` (EOF — the steady state for autopilot
    /// shim invocations whose stdin is `/dev/null`), the previous
    /// implementation broke out of the bridge loop. That dropped the
    /// daemon-facing UDS write half, which the daemon-side
    /// `pty_bridge_run` observed as `BridgeExit::ShimDisappeared`,
    /// firing the default `SIGTERM` cascade and reaping the spawned
    /// real binary mid-flight. Net effect: every `ember-gh pr create`
    /// from an autopilot script came back with exit code -15 and a
    /// missing credential injection.
    ///
    /// The fix transitions to `stdin_eof = true` and keeps the
    /// daemon→stdout half pumping until the daemon closes its end
    /// (natural child exit) or the main thread sets `done = true`.
    #[test]
    fn stdin_eof_does_not_request_teardown() {
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let mut buf = [0u8; 1024];
        let mut sink = Vec::<u8>::new();
        let outcome = pump_stdin_once(&mut stdin, &mut buf, &mut sink);
        assert!(matches!(outcome, PumpStdin::Eof));
        assert!(
            sink.is_empty(),
            "no TAG_DATA frame should be emitted for EOF"
        );
    }

    #[test]
    fn stdin_data_emits_framed_payload() {
        let payload = b"hello daemon";
        let mut stdin = Cursor::new(payload.to_vec());
        let mut buf = [0u8; 1024];
        let mut sink = Vec::<u8>::new();
        let outcome = pump_stdin_once(&mut stdin, &mut buf, &mut sink);
        assert!(matches!(outcome, PumpStdin::Continue));
        // TAG_DATA + 2-byte big-endian length + payload.
        assert_eq!(sink[0], TAG_DATA);
        let len = ((sink[1] as usize) << 8) | (sink[2] as usize);
        assert_eq!(len, payload.len());
        assert_eq!(&sink[3..3 + len], payload);
    }

    #[test]
    fn write_error_signals_teardown() {
        struct ErroringWriter;
        impl Write for ErroringWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "test"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut stdin = Cursor::new(b"x".to_vec());
        let mut buf = [0u8; 1024];
        let mut writer = ErroringWriter;
        let outcome = pump_stdin_once(&mut stdin, &mut buf, &mut writer);
        assert!(matches!(outcome, PumpStdin::WriteError));
    }

    #[test]
    fn wouldblock_returns_continue() {
        struct WouldBlockReader;
        impl Read for WouldBlockReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no data yet"))
            }
        }
        let mut stdin = WouldBlockReader;
        let mut buf = [0u8; 1024];
        let mut sink = Vec::<u8>::new();
        let outcome = pump_stdin_once(&mut stdin, &mut buf, &mut sink);
        assert!(matches!(outcome, PumpStdin::Continue));
        assert!(sink.is_empty());
    }

    enum ScriptedRead {
        Data(&'static [u8]),
        WouldBlock,
        Eof,
    }

    struct ScriptedReader {
        reads: VecDeque<ScriptedRead>,
    }

    impl Read for ScriptedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front().expect("scripted read step") {
                ScriptedRead::Data(bytes) => {
                    buf[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                }
                ScriptedRead::WouldBlock => {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, "scripted"))
                }
                ScriptedRead::Eof => Ok(0),
            }
        }
    }

    #[test]
    fn drain_daemon_output_flushes_all_pending_chunks_before_wouldblock() {
        let mut reader = ScriptedReader {
            reads: VecDeque::from(vec![
                ScriptedRead::Data(b"gh auth "),
                ScriptedRead::Data(b"failed"),
                ScriptedRead::WouldBlock,
            ]),
        };
        let mut stdout = Vec::<u8>::new();
        let mut buf = [0u8; 32];

        let outcome = drain_daemon_output(&mut reader, &mut stdout, &mut buf).expect("drain ok");

        assert!(matches!(outcome, DaemonOutputDrain::WouldBlock));
        assert_eq!(stdout, b"gh auth failed");
    }

    #[test]
    fn drain_daemon_output_preserves_bytes_before_eof() {
        let mut reader = ScriptedReader {
            reads: VecDeque::from(vec![ScriptedRead::Data(b"final stderr"), ScriptedRead::Eof]),
        };
        let mut stdout = Vec::<u8>::new();
        let mut buf = [0u8; 32];

        let outcome = drain_daemon_output(&mut reader, &mut stdout, &mut buf).expect("drain ok");

        assert!(matches!(outcome, DaemonOutputDrain::Eof));
        assert_eq!(stdout, b"final stderr");
    }
}
