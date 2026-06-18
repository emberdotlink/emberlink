//! CLASSIFICATION: PUBLIC
//!
//! Per-session loopback HTTPS egress proxy for the Cursor HOST lane.
//!
//! This is deliberately NOT a model-auth projector. Cursor owns its account
//! session and model credentials client-side, so Ember cannot honestly claim
//! governed model spend here. The value of this lane is narrower: launch-time
//! proxy mediation, Cursor-domain egress allowlisting, per-session teardown, and
//! audit rows that say what Cursor tried to dial.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use crate::infra::store::DaemonStore;

const MAX_PROXY_HEADER_BYTES: usize = 16 * 1024;
const CURSOR_EGRESS_EVENT: &str = "cursor.egress";

/// Everything the registry needs to stand up a per-session Cursor egress
/// listener. The std listener is bound synchronously on `register_session` so
/// the launcher can receive the ephemeral URL in that same RPC response.
pub struct CursorEgressOpenSpec {
    pub session_id: String,
    pub runtime_persona_id: String,
    pub listener: StdTcpListener,
    /// Kept for audit/parity with other loopback lanes. A non-root daemon
    /// cannot enforce TCP peer identity on loopback.
    pub bound_uid: u32,
}

impl std::fmt::Debug for CursorEgressOpenSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorEgressOpenSpec")
            .field("session_id", &self.session_id)
            .field("runtime_persona_id", &self.runtime_persona_id)
            .field("bound_uid", &self.bound_uid)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum CursorEgressCommand {
    Open(CursorEgressOpenSpec),
    Close { session_id: String },
}

static CURSOR_EGRESS_COMMAND_TX: OnceLock<mpsc::UnboundedSender<CursorEgressCommand>> =
    OnceLock::new();
static CURSOR_EGRESS_PORTS: OnceLock<Mutex<HashMap<String, u16>>> = OnceLock::new();

fn cursor_egress_ports() -> &'static Mutex<HashMap<String, u16>> {
    CURSOR_EGRESS_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn install_cursor_egress_command_sender(
    tx: mpsc::UnboundedSender<CursorEgressCommand>,
) -> bool {
    CURSOR_EGRESS_COMMAND_TX.set(tx).is_ok()
}

pub fn request_open_cursor_egress(
    session_id: &str,
    runtime_persona_id: &str,
    bound_uid: u32,
) -> Option<u16> {
    let listener = match StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(session_id, error = %e, "cursor_egress_proxy: failed to bind loopback listener");
            return None;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            tracing::warn!(session_id, error = %e, "cursor_egress_proxy: failed to read local_addr");
            return None;
        }
    };

    cursor_egress_ports()
        .lock()
        .unwrap()
        .insert(session_id.to_string(), port);

    let spec = CursorEgressOpenSpec {
        session_id: session_id.to_string(),
        runtime_persona_id: runtime_persona_id.to_string(),
        listener,
        bound_uid,
    };
    if !send_command(CursorEgressCommand::Open(spec)) {
        cursor_egress_ports().lock().unwrap().remove(session_id);
        return None;
    }
    Some(port)
}

pub fn request_close_cursor_egress(session_id: &str) -> bool {
    cursor_egress_ports().lock().unwrap().remove(session_id);
    send_command(CursorEgressCommand::Close {
        session_id: session_id.to_string(),
    })
}

pub fn cursor_egress_url_for(session_id: &str) -> Option<String> {
    let port = *cursor_egress_ports().lock().unwrap().get(session_id)?;
    Some(format!("http://127.0.0.1:{port}"))
}

fn send_command(cmd: CursorEgressCommand) -> bool {
    match CURSOR_EGRESS_COMMAND_TX.get() {
        Some(tx) => match tx.send(cmd) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "cursor_egress_proxy: registry receiver gone — command dropped");
                false
            }
        },
        None => {
            tracing::debug!("cursor_egress_proxy: command channel not installed — command dropped");
            false
        }
    }
}

struct CursorEgressEntry {
    shutdown_tx: watch::Sender<bool>,
}

impl CursorEgressEntry {
    fn tear_down(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

fn open_cursor_egress_socket(
    spec: CursorEgressOpenSpec,
    store: Rc<DaemonStore>,
) -> io::Result<CursorEgressEntry> {
    let CursorEgressOpenSpec {
        session_id,
        runtime_persona_id,
        listener,
        bound_uid,
    } = spec;

    listener.set_nonblocking(true)?;
    let tokio_listener = tokio::net::TcpListener::from_std(listener)?;
    let port = tokio_listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_session_id = session_id.clone();
    let log_session_id = session_id.clone();
    tokio::task::spawn_local(async move {
        run_cursor_egress_accept_loop(
            tokio_listener,
            session_id,
            runtime_persona_id,
            bound_uid,
            store,
            shutdown_rx,
        )
        .await;
        tracing::debug!(session_id = %loop_session_id, "cursor_egress_proxy: accept loop exited");
    });

    tracing::info!(
        session_id = %log_session_id,
        port,
        bound_uid,
        "cursor_egress_proxy: per-session loopback HTTPS proxy up (egress/audit only; no model credential brokering)"
    );

    Ok(CursorEgressEntry { shutdown_tx })
}

async fn run_cursor_egress_accept_loop(
    listener: tokio::net::TcpListener,
    session_id: String,
    runtime_persona_id: String,
    bound_uid: u32,
    store: Rc<DaemonStore>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let store = Rc::clone(&store);
                        let session_id = session_id.clone();
                        let runtime_persona_id = runtime_persona_id.clone();
                        tokio::task::spawn_local(async move {
                            handle_cursor_egress_connection(
                                stream,
                                store,
                                session_id,
                                runtime_persona_id,
                                bound_uid,
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "cursor_egress_proxy: accept error");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn handle_cursor_egress_connection(
    mut client: tokio::net::TcpStream,
    store: Rc<DaemonStore>,
    session_id: String,
    runtime_persona_id: String,
    bound_uid: u32,
) {
    let peer_addr = client.peer_addr().ok().map(|addr| addr.to_string());
    let (header, pending) = match read_proxy_header(&mut client).await {
        Ok(parts) => parts,
        Err(e) => {
            audit_cursor_egress(
                &store,
                &runtime_persona_id,
                &session_id,
                None,
                None,
                bound_uid,
                "denied",
                &format!(
                    "malformed_request error={e} peer_addr={}",
                    peer_addr.as_deref().unwrap_or("unknown")
                ),
            );
            let _ =
                write_proxy_response(&mut client, 400, "Bad Request", "malformed proxy request")
                    .await;
            return;
        }
    };

    let request_line = first_request_line(&header).unwrap_or("");
    let method = request_line.split_whitespace().next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        audit_cursor_egress(
            &store,
            &runtime_persona_id,
            &session_id,
            None,
            None,
            bound_uid,
            "denied",
            &format!(
                "unsupported_method method={method} peer_addr={}",
                peer_addr.as_deref().unwrap_or("unknown")
            ),
        );
        let _ = write_proxy_response(
            &mut client,
            405,
            "Method Not Allowed",
            "only CONNECT is supported",
        )
        .await;
        return;
    }

    let target = match parse_connect_target(&header) {
        Ok(target) => target,
        Err(reason) => {
            audit_cursor_egress(
                &store,
                &runtime_persona_id,
                &session_id,
                None,
                None,
                bound_uid,
                "denied",
                &format!(
                    "bad_connect_target reason={reason} peer_addr={}",
                    peer_addr.as_deref().unwrap_or("unknown")
                ),
            );
            let _ = write_proxy_response(&mut client, 400, "Bad Request", "invalid CONNECT target")
                .await;
            return;
        }
    };

    if target.port != 443 {
        audit_cursor_egress(
            &store,
            &runtime_persona_id,
            &session_id,
            Some(&target.host),
            Some(target.port),
            bound_uid,
            "denied",
            "port_not_allowed",
        );
        let _ = write_proxy_response(
            &mut client,
            403,
            "Forbidden",
            "cursor egress proxy allows CONNECT port 443 only",
        )
        .await;
        return;
    }

    if !cursor_host_allowed(&target.host) {
        audit_cursor_egress(
            &store,
            &runtime_persona_id,
            &session_id,
            Some(&target.host),
            Some(target.port),
            bound_uid,
            "denied",
            "host_not_allowed",
        );
        let _ = write_proxy_response(
            &mut client,
            403,
            "Forbidden",
            "target host is not on the Cursor allowlist",
        )
        .await;
        return;
    }

    let mut upstream = match tokio::net::TcpStream::connect((target.host.as_str(), target.port))
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            audit_cursor_egress(
                &store,
                &runtime_persona_id,
                &session_id,
                Some(&target.host),
                Some(target.port),
                bound_uid,
                "error",
                &format!("upstream_connect_failed error={e}"),
            );
            let _ =
                write_proxy_response(&mut client, 502, "Bad Gateway", "upstream connect failed")
                    .await;
            return;
        }
    };

    audit_cursor_egress(
        &store,
        &runtime_persona_id,
        &session_id,
        Some(&target.host),
        Some(target.port),
        bound_uid,
        "allowed",
        "connect_established",
    );

    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    if !pending.is_empty() && upstream.write_all(&pending).await.is_err() {
        return;
    }
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        tracing::debug!(
            session_id = %session_id,
            host = %target.host,
            port = target.port,
            error = %e,
            "cursor_egress_proxy: tunnel closed with io error"
        );
    }
}

fn audit_cursor_egress(
    store: &DaemonStore,
    runtime_persona_id: &str,
    session_id: &str,
    host: Option<&str>,
    port: Option<u16>,
    bound_uid: u32,
    outcome: &str,
    reason: &str,
) {
    let detail = format!(
        "session_id={session_id} host={} port={} bound_uid={bound_uid} lane=cursor-egress reason={reason}",
        host.unwrap_or("unknown"),
        port.map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    );
    if let Err(e) = store.log_event(
        Some(runtime_persona_id),
        CURSOR_EGRESS_EVENT,
        None,
        outcome,
        Some(&detail),
    ) {
        tracing::warn!(
            session_id,
            error = ?e,
            "cursor_egress_proxy: failed to write audit event"
        );
    }
    tracing::info!(
        session_id,
        host = host.unwrap_or("unknown"),
        port = port.unwrap_or(0),
        bound_uid,
        outcome,
        reason,
        "cursor_egress_proxy: egress decision"
    );
}

async fn read_proxy_header(stream: &mut tokio::net::TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut scratch = [0u8; 1024];
    loop {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before proxy header",
            ));
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(end) = find_header_end(&buf) {
            let pending = buf.split_off(end);
            return Ok((buf, pending));
        }
        if buf.len() > MAX_PROXY_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy header exceeded maximum size",
            ));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn first_request_line(header: &[u8]) -> Option<&str> {
    let header = std::str::from_utf8(header).ok()?;
    header.lines().next()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectTarget {
    host: String,
    port: u16,
}

fn parse_connect_target(header: &[u8]) -> Result<ConnectTarget, String> {
    let first_line = first_request_line(header).ok_or_else(|| "invalid_utf8".to_string())?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or_else(|| "missing_method".to_string())?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err("method_not_connect".to_string());
    }
    let authority = parts
        .next()
        .ok_or_else(|| "missing_authority".to_string())?;
    let version = parts.next().ok_or_else(|| "missing_version".to_string())?;
    if parts.next().is_some() {
        return Err("too_many_request_line_fields".to_string());
    }
    if !version.starts_with("HTTP/") {
        return Err("invalid_version".to_string());
    }
    parse_connect_authority(authority)
}

fn parse_connect_authority(authority: &str) -> Result<ConnectTarget, String> {
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('/')
        || authority.starts_with('[')
        || authority.chars().any(char::is_whitespace)
    {
        return Err("invalid_authority".to_string());
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| "missing_port".to_string())?;
    if host.is_empty() || port.is_empty() || host.contains(':') {
        return Err("invalid_host_port".to_string());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid_port".to_string())?;
    let host = normalize_host(host)?;
    Ok(ConnectTarget { host, port })
}

fn normalize_host(host: &str) -> Result<String, String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host.is_ascii()
        || host
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
    {
        return Err("invalid_host".to_string());
    }
    Ok(host)
}

fn cursor_host_allowed(host: &str) -> bool {
    let Ok(host) = normalize_host(host) else {
        return false;
    };
    ["cursor.com", "cursor.sh"]
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

async fn write_proxy_response(
    stream: &mut tokio::net::TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

pub async fn run_cursor_egress_proxy_registry(
    store: Rc<DaemonStore>,
    mut commands: mpsc::UnboundedReceiver<CursorEgressCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions: HashMap<String, CursorEgressEntry> = HashMap::new();

    loop {
        tokio::select! {
            cmd = commands.recv() => {
                match cmd {
                    Some(CursorEgressCommand::Open(spec)) => {
                        let session_id = spec.session_id.clone();
                        if let Some(prev) = sessions.remove(&session_id) {
                            prev.tear_down();
                        }
                        match open_cursor_egress_socket(spec, Rc::clone(&store)) {
                            Ok(entry) => {
                                sessions.insert(session_id, entry);
                            }
                            Err(e) => {
                                tracing::warn!(session_id = %session_id, error = %e, "cursor_egress_proxy: failed to open per-session listener");
                                cursor_egress_ports().lock().unwrap().remove(&session_id);
                            }
                        }
                    }
                    Some(CursorEgressCommand::Close { session_id }) => {
                        if let Some(entry) = sessions.remove(&session_id) {
                            entry.tear_down();
                            tracing::info!(session_id = %session_id, "cursor_egress_proxy: per-session listener torn down");
                        }
                    }
                    None => {
                        tracing::debug!("cursor_egress_proxy: command channel closed — registry exiting");
                        break;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    for (_id, entry) in sessions.drain() {
        entry.tear_down();
    }
    tracing::debug!("cursor_egress_proxy: registry loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_allowlist_accepts_cursor_domains() {
        assert!(cursor_host_allowed("cursor.com"));
        assert!(cursor_host_allowed("api2.cursor.sh"));
        assert!(cursor_host_allowed("www.cursor.com."));
        assert!(cursor_host_allowed("deep.api.cursor.com"));
    }

    #[test]
    fn cursor_allowlist_rejects_boundary_bypass() {
        assert!(!cursor_host_allowed("evilcursor.com"));
        assert!(!cursor_host_allowed("cursor.com.evil.test"));
        assert!(!cursor_host_allowed("cursor.sh.evil"));
        assert!(!cursor_host_allowed("cursor_com"));
    }

    #[test]
    fn parse_connect_target_normalizes_host_and_port() {
        let target =
            parse_connect_target(b"CONNECT API2.Cursor.SH:443 HTTP/1.1\r\n\r\n").expect("target");
        assert_eq!(
            target,
            ConnectTarget {
                host: "api2.cursor.sh".to_string(),
                port: 443,
            }
        );
    }

    #[test]
    fn parse_connect_target_rejects_bad_authorities() {
        for header in [
            b"CONNECT cursor.com HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT user@cursor.com:443 HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n".as_slice(),
            b"CONNECT cursor.com:abc HTTP/1.1\r\n\r\n".as_slice(),
            b"GET http://cursor.com/ HTTP/1.1\r\n\r\n".as_slice(),
        ] {
            assert!(parse_connect_target(header).is_err());
        }
    }

    #[test]
    fn url_for_none_before_open() {
        assert!(cursor_egress_url_for("sess_cursor_never_opened_xyz").is_none());
    }

    #[test]
    fn publish_then_url_then_remove() {
        let sid = "sess_cursor_unit_publish";
        cursor_egress_ports()
            .lock()
            .unwrap()
            .insert(sid.to_string(), 61234);
        assert_eq!(
            cursor_egress_url_for(sid).as_deref(),
            Some("http://127.0.0.1:61234")
        );
        cursor_egress_ports().lock().unwrap().remove(sid);
        assert!(cursor_egress_url_for(sid).is_none());
    }

    #[test]
    fn request_open_cursor_egress_binds_loopback() {
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback(), "must bind loopback, got {addr}");
        assert_ne!(addr.port(), 0, "ephemeral port must be non-zero once bound");
    }

    #[test]
    fn request_open_cursor_egress_rolls_back_port_when_registry_absent() {
        let sid = "sess_cursor_rollback";
        let result = request_open_cursor_egress(sid, "persona_cursor", 1000);
        if result.is_none() {
            assert!(
                cursor_egress_url_for(sid).is_none(),
                "port must be rolled back when registry is absent"
            );
        } else {
            request_close_cursor_egress(sid);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn denied_connect_returns_403_and_writes_audit() {
        let store = Rc::new(DaemonStore::open_in_memory().expect("store"));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server_store = Rc::clone(&store);
        let server = async move {
            let (stream, _) = listener.accept().await.expect("accept client");
            handle_cursor_egress_connection(
                stream,
                server_store,
                "sess_cursor_denied".to_string(),
                "persona_cursor".to_string(),
                501,
            )
            .await;
        };

        let client = async move {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect proxy");
            stream
                .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
                .await
                .expect("write request");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("read response");
            String::from_utf8(response).expect("utf8 response")
        };

        let ((), response) = tokio::join!(server, client);
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "unexpected response: {response:?}"
        );

        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter::default())
            .expect("audit query");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.agent_id.as_deref(), Some("persona_cursor"));
        assert_eq!(entry.action, CURSOR_EGRESS_EVENT);
        assert_eq!(entry.outcome, "denied");
        let details = entry.details.as_deref().expect("details");
        assert!(details.contains("session_id=sess_cursor_denied"));
        assert!(details.contains("host=evil.example"));
        assert!(details.contains("reason=host_not_allowed"));
    }
}
