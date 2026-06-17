//! CLASSIFICATION: PUBLIC
//! Launcher-side browser presence helpers.
//!
//! The shipped local launcher path is still direct Unix-socket `register_session`
//! success. The browser/session-open bridge remains partial on the daemon side, so
//! this module deliberately exposes explicit `Unsupported` behavior instead of
//! panic-style scaffolding when the reserved presence branch is encountered.

use std::io;
use std::path::Path;

/// A signed handle minted by the daemon after the user completes Touch ID.
///
/// This remains target-state only. The production daemon handler for the
/// browser/session-open bridge is not yet available to launcher callers.
#[derive(Debug, Clone)]
pub struct DaemonSignedHandle {
    /// Opaque handle token returned by the daemon.
    pub token: String,
    /// The `prompt_id` this handle was minted for.
    pub prompt_id: String,
}

/// Thin placeholder client over the daemon Unix socket.
///
/// Retained so the reserved session-open presence branch has a stable client
/// shape once the daemon contract exists.
pub struct Client {
    socket_path: std::path::PathBuf,
}

impl Client {
    /// Build a `Client` for the given daemon socket path.
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
        }
    }

    /// Return the socket path this client is bound to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn unsupported_presence_flow_error(
    socket_path: &Path,
    prompt_id: &str,
    tab_url: Option<&str>,
    stage: &str,
) -> io::Error {
    let mut message = format!(
        "{stage}: browser/session-open presence flow is not shipped yet; \
         current launcher posture is direct local register_session over the daemon UDS \
         (socket={})",
        socket_path.display()
    );
    if !prompt_id.is_empty() {
        message.push_str(&format!(", prompt_id={prompt_id}"));
    }
    if let Some(url) = tab_url
        && !url.is_empty()
    {
        message.push_str(&format!(", tab_url={url}"));
    }
    message.push_str(
        ". The daemon does not yet expose a production session-open retry/handle-delivery \
         contract for this branch.",
    );
    io::Error::new(io::ErrorKind::Unsupported, message)
}

pub(crate) fn session_open_presence_unavailable(
    socket_path: &Path,
    prompt_id: &str,
    tab_url: &str,
) -> io::Error {
    unsupported_presence_flow_error(socket_path, prompt_id, Some(tab_url), "register_session")
}

/// Open the dashboard presence-prompt tab in the system browser.
///
/// Platform dispatch:
/// - Linux: `xdg-open <url>`
/// - macOS: `open <url>`
/// - Windows: `cmd /c start <url>`
///
/// On failure the URL is printed to stderr so the operator can paste it
/// manually — the launcher must not block silently on a missing browser.
pub fn open_presence_prompt(url: &str) -> Result<(), io::Error> {
    open_presence_prompt_with(url, _open_url)
}

fn open_presence_prompt_with(
    url: &str,
    opener: impl FnOnce(&str) -> Result<(), io::Error>,
) -> Result<(), io::Error> {
    if url.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "open_presence_prompt: url must not be empty",
        ));
    }

    let result = opener(url);
    if let Err(ref e) = result {
        eprintln!(
            "ember: could not open browser for presence prompt ({}); \
             open this URL manually:\n  {}",
            e, url
        );
    }
    result
}

/// Internal: platform-dispatched browser-open. Factored out so unit tests can
/// verify the dispatch logic without touching the real URL.
#[cfg(target_os = "linux")]
fn _open_url(url: &str) -> Result<(), io::Error> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), format!("xdg-open failed: {e}")))
}

#[cfg(target_os = "macos")]
fn _open_url(url: &str) -> Result<(), io::Error> {
    std::process::Command::new("open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), format!("open failed: {e}")))
}

#[cfg(target_os = "windows")]
fn _open_url(url: &str) -> Result<(), io::Error> {
    std::process::Command::new("cmd")
        .args(["/c", "start", url])
        .spawn()
        .map(|_| ())
        .map_err(|e| io::Error::new(e.kind(), format!("cmd /c start failed: {e}")))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn _open_url(url: &str) -> Result<(), io::Error> {
    // Unsupported platform: fall through to the stderr-fallback in
    // `open_presence_prompt` so the operator sees the URL.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("browser-open not supported on this platform; open manually: {url}"),
    ))
}

/// Resolve a daemon-signed presence handle for `prompt_id`.
///
/// This currently returns a structured `Unsupported` error because the daemon
/// does not yet expose a production handle-delivery contract for launcher
/// callers.
pub async fn await_presence_handle(
    daemon_client: &Client,
    prompt_id: &str,
) -> Result<DaemonSignedHandle, io::Error> {
    if prompt_id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "await_presence_handle: prompt_id must not be empty",
        ));
    }

    Err(unsupported_presence_flow_error(
        daemon_client.socket_path(),
        prompt_id,
        None,
        "await_presence_handle",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_presence_prompt_rejects_empty_url() {
        let err = open_presence_prompt("").expect_err("must reject empty URL");
        assert!(
            err.kind() == io::ErrorKind::InvalidInput,
            "expected InvalidInput, got {:?}",
            err.kind()
        );
        assert!(
            err.to_string().contains("url must not be empty"),
            "error must mention empty url: {err}"
        );
    }

    #[test]
    fn open_presence_prompt_non_empty_url_reaches_dispatch_hook_without_opening_browser() {
        let mut dispatched = None;
        open_presence_prompt_with("http://localhost:9999/prompt/test-id", |url| {
            dispatched = Some(url.to_string());
            Ok(())
        })
        .expect("well-formed URL should reach the dispatch hook");
        assert_eq!(
            dispatched.as_deref(),
            Some("http://localhost:9999/prompt/test-id"),
            "open_presence_prompt should pass the exact URL to the dispatch hook"
        );
    }

    #[test]
    fn open_presence_prompt_propagates_dispatch_error_without_invalid_input() {
        let err = open_presence_prompt_with("http://localhost:9999/prompt/test-id", |_| {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "stub failure",
            ))
        })
        .expect_err("dispatch failure should surface");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn client_stores_socket_path() {
        let path = Path::new("/tmp/daemon.sock");
        let client = Client::new(path);
        assert_eq!(client.socket_path(), path);
    }

    #[test]
    fn daemon_signed_handle_carries_fields() {
        let h = DaemonSignedHandle {
            token: "tok_abc".to_string(),
            prompt_id: "prompt_xyz".to_string(),
        };
        assert_eq!(h.token, "tok_abc");
        assert_eq!(h.prompt_id, "prompt_xyz");
    }

    #[tokio::test]
    async fn await_presence_handle_rejects_empty_prompt_id() {
        let client = Client::new(Path::new("/tmp/daemon.sock"));
        let err = await_presence_handle(&client, "")
            .await
            .expect_err("empty prompt_id must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("prompt_id must not be empty"),
            "error must explain invalid prompt_id: {err}"
        );
    }

    #[tokio::test]
    async fn await_presence_handle_returns_structured_unavailable_error() {
        let client = Client::new(Path::new("/tmp/daemon.sock"));
        let err = await_presence_handle(&client, "prompt_123")
            .await
            .expect_err("reserved bridge must refuse cleanly");
        let msg = err.to_string();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(
            msg.contains("browser/session-open presence flow is not shipped yet"),
            "error must explain current state: {msg}"
        );
        assert!(
            msg.contains("socket=/tmp/daemon.sock"),
            "error must carry socket path context: {msg}"
        );
        assert!(
            msg.contains("prompt_id=prompt_123"),
            "error must carry prompt_id context: {msg}"
        );
    }
}
