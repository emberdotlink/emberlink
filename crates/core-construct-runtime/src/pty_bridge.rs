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
    let mut ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
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
        libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, sigterm_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTSTP, sigtstp_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGCONT, sigcont_handler as *const () as libc::sighandler_t);
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
    listener.set_nonblocking(false).ok();

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

    read_stream.set_nonblocking(true).ok();

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut buf = [0u8; 4096];
    let mut stdin_buf = [0u8; 4096];

    loop {
        if let Ok(d) = done.lock()
            && *d
        {
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

        // Read from daemon (child pty output) → our stdout.
        match read_stream.read(&mut buf) {
            Ok(0) => break,
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
