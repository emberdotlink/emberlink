//! JSON-RPC-over-UDS client for the ember daemon.
//!
//! Wire format: newline-delimited JSON per handler.rs::dispatch_method:
//!   → `{"id":"1","method":<method>,"params":<params>}\n`
//!   ← `{"id":"1","result":<result>}\n`  or  `{"id":"1","error":{...}}\n`
//!
//! Matches `call_daemon` in crates/emberlink-cli/src/broker.rs (same wire
//! shape, same error-extraction logic).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream as StdTcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Daemon transport resolution
// ---------------------------------------------------------------------------
//
// Subtask A of ARCH-CORE-CONSTRUCT-RUNTIME-MTLS-TCP-TRANSPORT. The
// construct shims (`ember-gh`, `ember-git`, etc.) historically only
// dialed the daemon over a host-local Unix socket. ADR 154 §Component 1
// adds an in-container path that has to traverse the host boundary via
// an mTLS-protected TCP listener (the ember-rpc Phase C surface). This
// module now owns both transport selection and the actual client dial.
//
// Anchor: `construct_runtime_mtls_tcp_transport_decide`.

/// Which transport a construct shim should use to reach the daemon.
///
/// Carries enough state for the dial to proceed without re-reading env
/// vars. The client matches on this enum to pick the right connect path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonTransport {
    /// Host-local Unix socket. Used when the shim runs on the same host
    /// as the daemon (no container boundary).
    Uds(PathBuf),
    /// In-container mTLS+TCP path. The URL typically points at
    /// `https://host.docker.internal:4243` (the host's ember-rpc
    /// listener). Cert paths can come either from the explicit bridge
    /// env vars (`EMBER_CLIENT_CERT`, `EMBER_CLIENT_KEY`, `EMBER_CA_CERT`)
    /// or from a cert dir override.
    MtlsTcp {
        url: String,
        server_name: String,
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_path: PathBuf,
    },
}

const DEFAULT_CLIENT_CERT_PATH: &str = "/run/ember/client.crt";
const DEFAULT_CLIENT_KEY_PATH: &str = "/run/ember/client.key";
const DEFAULT_CA_CERT_PATH: &str = "/run/ember/ca.crt";
const DEFAULT_BRIDGE_SERVER_NAME: &str = "localhost";

/// Resolve the daemon UDS path.
///
/// Precedence:
///   1. `EMBER_SOCKET_PATH` env var (used by qember.sh + integration tests)
///   2. `~/.ember/run/daemon.sock` (matches DaemonConfig::default())
///   3. `/tmp/.ember/run/daemon.sock` if $HOME is unset
///
/// Retained as a stable public API — existing callers that always want
/// the UDS path call this directly. New callers reach for
/// [`decide_transport`] instead so they pick up the in-container
/// fallback for free.
pub fn daemon_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("EMBER_SOCKET_PATH") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".ember").join("run").join("daemon.sock")
}

/// Choose the transport for a construct shim's daemon RPC.
///
/// Selection rule (matches ADR 154 §Component 1 + ADR 166 §Component 3):
///
///   1. If `EMBER_BRIDGE_URL` is set and non-empty, the shim is running
///      in-container and reaches the daemon via mTLS+TCP. Client cert
///      material resolves in precedence order:
///      explicit `EMBER_CLIENT_CERT` / `EMBER_CLIENT_KEY` / `EMBER_CA_CERT`
///      paths, then `EMBER_BRIDGE_CERT_DIR`, then the canonical
///      `/run/ember/*.crt` defaults (the one in-container bridge contract,
///      ADR 215 §4). `EMBER_DAEMON_SERVER_NAME` overrides the TLS SNI /
///      SAN expectation; default is `localhost`.
///   2. Otherwise the shim is host-resident; dial the UDS resolved by
///      [`daemon_socket_path`].
///
/// Pure — every input comes from `std::env::var_os`; no I/O. Callers
/// match on the returned enum to pick the connect path.
/// construct_runtime_mtls_tcp_transport_decide.
pub fn decide_transport() -> DaemonTransport {
    if let Some(url) = std::env::var_os("EMBER_BRIDGE_URL")
        && let Some(s) = url.to_str()
        && !s.is_empty()
    {
        let cert_dir = std::env::var_os("EMBER_BRIDGE_CERT_DIR").map(PathBuf::from);
        let cert_path = std::env::var_os("EMBER_CLIENT_CERT")
            .map(PathBuf::from)
            .or_else(|| cert_dir.as_ref().map(|dir| dir.join("client.crt")))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CLIENT_CERT_PATH));
        let key_path = std::env::var_os("EMBER_CLIENT_KEY")
            .map(PathBuf::from)
            .or_else(|| cert_dir.as_ref().map(|dir| dir.join("client.key")))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CLIENT_KEY_PATH));
        let ca_path = std::env::var_os("EMBER_CA_CERT")
            .map(PathBuf::from)
            .or_else(|| cert_dir.as_ref().map(|dir| dir.join("ca.crt")))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CA_CERT_PATH));
        let server_name = std::env::var("EMBER_DAEMON_SERVER_NAME")
            .unwrap_or_else(|_| DEFAULT_BRIDGE_SERVER_NAME.to_string());
        return DaemonTransport::MtlsTcp {
            url: s.to_string(),
            server_name,
            cert_path,
            key_path,
            ca_path,
        };
    }
    DaemonTransport::Uds(daemon_socket_path())
}

// ---------------------------------------------------------------------------
// RPC errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RpcError {
    DaemonUnavailable(String),
    Io(String),
    Protocol(String),
    DaemonRpc {
        code: i32,
        message: String,
        data: Option<Value>,
    },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::DaemonUnavailable(s) => write!(f, "daemon unavailable: {s}"),
            RpcError::Io(s) => write!(f, "io: {s}"),
            RpcError::Protocol(s) => write!(f, "protocol: {s}"),
            RpcError::DaemonRpc { code, message, .. } => {
                write!(f, "daemon rpc error {code}: {message}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RPC call
// ---------------------------------------------------------------------------

/// Send one JSON-RPC request over the daemon socket and return the `result`.
pub fn call_daemon_rpc(
    socket_path: &std::path::Path,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    call_daemon_rpc_uds(socket_path, method, params, None)
}

/// Like [`call_daemon_rpc`] but applies read+write timeouts to the socket.
///
/// Used by best-effort fire-and-forget callers that must not block on a
/// hung daemon — e.g. `log_unsessioned_subprocess` in runtime.rs, which
/// runs in the shim's passthrough branch and adds latency to every
/// invocation of every wrapped tool. A daemon under load (or a stale UDS
/// pointing at a dead socket file) would otherwise stall the shim past
/// any reasonable threshold.
///
/// The timeout applies to each read/write operation, not the whole
/// exchange — a malicious daemon that drips bytes could still extend the
/// total runtime, but the worst case is bounded by the daemon's own
/// per-request handler timeout. For best-effort callers the trade-off is
/// acceptable.
pub fn call_daemon_rpc_with_timeout(
    socket_path: &std::path::Path,
    method: &str,
    params: &Value,
    timeout: Duration,
) -> Result<Value, RpcError> {
    call_daemon_rpc_uds(socket_path, method, params, Some(timeout))
}

pub fn call_daemon_rpc_transport(
    transport: &DaemonTransport,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    call_daemon_rpc_transport_with_timeout(transport, method, params, None)
}

pub fn call_daemon_rpc_transport_with_timeout(
    transport: &DaemonTransport,
    method: &str,
    params: &Value,
    timeout: Option<Duration>,
) -> Result<Value, RpcError> {
    match transport {
        DaemonTransport::Uds(socket_path) => {
            call_daemon_rpc_uds(socket_path, method, params, timeout)
        }
        DaemonTransport::MtlsTcp {
            url,
            server_name,
            cert_path,
            key_path,
            ca_path,
        } => call_daemon_rpc_mtls(
            url,
            server_name,
            cert_path,
            key_path,
            ca_path,
            method,
            params,
            timeout,
        ),
    }
}

pub fn call_daemon_rpc_current_env(method: &str, params: &Value) -> Result<Value, RpcError> {
    let transport = decide_transport();
    call_daemon_rpc_transport(&transport, method, params)
}

pub fn call_daemon_rpc_current_env_with_timeout(
    method: &str,
    params: &Value,
    timeout: Duration,
) -> Result<Value, RpcError> {
    let transport = decide_transport();
    call_daemon_rpc_transport_with_timeout(&transport, method, params, Some(timeout))
}

fn call_daemon_rpc_uds(
    socket_path: &std::path::Path,
    method: &str,
    params: &Value,
    timeout: Option<Duration>,
) -> Result<Value, RpcError> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| RpcError::DaemonUnavailable(format_daemon_unavailable(socket_path, &e)))?;

    if let Some(t) = timeout {
        stream
            .set_read_timeout(Some(t))
            .map_err(|e| RpcError::Io(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(t))
            .map_err(|e| RpcError::Io(format!("set_write_timeout: {e}")))?;
    }

    let mut writer = stream
        .try_clone()
        .map_err(|e| RpcError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);
    let request = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| RpcError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| RpcError::Io(format!("read response: {e}")))?;

    parse_json_rpc_response(&response_line)
}

fn format_daemon_unavailable(socket_path: &Path, error: &std::io::Error) -> String {
    let mut msg = format!("{}: {error}", socket_path.display());
    let bridge_env_missing = std::env::var_os("EMBER_BRIDGE_URL").is_none();
    let looks_like_container_bridge_socket = socket_path
        .to_str()
        .map(|s| s.starts_with("/run/ember/") || s.starts_with("/run/emberd-host/"))
        .unwrap_or(false);
    if bridge_env_missing && looks_like_container_bridge_socket {
        msg.push_str(
            " — isolated/container brokered tool RPC still needs EMBER_BRIDGE_URL plus client cert wiring; host-mounted UDS is not the cross-boundary path",
        );
    }
    msg
}

fn bridge_endpoint_from_url(url: &str) -> Result<&str, RpcError> {
    let stripped = if let Some((_, rest)) = url.split_once("://") {
        rest
    } else {
        url
    };
    let endpoint = stripped.split('/').next().unwrap_or("");
    if endpoint.is_empty() {
        return Err(RpcError::Protocol(format!(
            "invalid EMBER_BRIDGE_URL (missing endpoint): {url}"
        )));
    }
    Ok(endpoint)
}

fn load_bridge_client_tls_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<Arc<ClientConfig>, RpcError> {
    let cert_bytes = std::fs::read(cert_path)
        .map_err(|e| RpcError::Io(format!("read client cert {}: {e}", cert_path.display())))?;
    let key_bytes = std::fs::read(key_path)
        .map_err(|e| RpcError::Io(format!("read client key {}: {e}", key_path.display())))?;
    let ca_bytes = std::fs::read(ca_path)
        .map_err(|e| RpcError::Io(format!("read CA cert {}: {e}", ca_path.display())))?;

    let client_certs: Vec<CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(cert_bytes);
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                RpcError::Protocol(format!("parse client cert {}: {e}", cert_path.display()))
            })?
    };
    if client_certs.is_empty() {
        return Err(RpcError::Protocol(format!(
            "client cert {} contained no certificates",
            cert_path.display()
        )));
    }

    let client_key: PrivateKeyDer<'static> = {
        let mut cursor = std::io::Cursor::new(key_bytes);
        rustls_pemfile::private_key(&mut cursor)
            .map_err(|e| {
                RpcError::Protocol(format!("parse client key {}: {e}", key_path.display()))
            })?
            .ok_or_else(|| {
                RpcError::Protocol(format!(
                    "client key {} contained no private key",
                    key_path.display()
                ))
            })?
    };

    let ca_certs: Vec<CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(ca_bytes);
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RpcError::Protocol(format!("parse CA cert {}: {e}", ca_path.display())))?
    };
    if ca_certs.is_empty() {
        return Err(RpcError::Protocol(format!(
            "CA cert {} contained no certificates",
            ca_path.display()
        )));
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = RootCertStore::empty();
    for ca in ca_certs {
        root_store
            .add(ca)
            .map_err(|e| RpcError::Protocol(format!("add CA to root store: {e}")))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| RpcError::Protocol(format!("build client TLS config: {e}")))?;
    Ok(Arc::new(config))
}

// RPC/plumbing signature — structurally many params (url/TLS paths/method/params/timeout).
#[allow(clippy::too_many_arguments)]
fn call_daemon_rpc_mtls(
    url: &str,
    server_name: &str,
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
    method: &str,
    params: &Value,
    timeout: Option<Duration>,
) -> Result<Value, RpcError> {
    let endpoint = bridge_endpoint_from_url(url)?;
    let tcp = StdTcpStream::connect(endpoint)
        .map_err(|e| RpcError::DaemonUnavailable(format!("{url}: {e}")))?;
    if let Some(t) = timeout {
        tcp.set_read_timeout(Some(t))
            .map_err(|e| RpcError::Io(format!("set bridge read timeout: {e}")))?;
        tcp.set_write_timeout(Some(t))
            .map_err(|e| RpcError::Io(format!("set bridge write timeout: {e}")))?;
    }

    let tls_config = load_bridge_client_tls_config(cert_path, key_path, ca_path)?;
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|e| RpcError::Protocol(format!("invalid bridge server name: {e}")))?;
    let conn = ClientConnection::new(tls_config, server_name)
        .map_err(|e| RpcError::Protocol(format!("bridge TLS client init: {e}")))?;
    let mut tls_stream = StreamOwned::new(conn, tcp);

    let request = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');
    tls_stream
        .write_all(line.as_bytes())
        .map_err(|e| RpcError::Io(format!("write bridge request: {e}")))?;
    tls_stream
        .flush()
        .map_err(|e| RpcError::Io(format!("flush bridge request: {e}")))?;

    let mut reader = BufReader::new(tls_stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| RpcError::Io(format!("read bridge response: {e}")))?;

    parse_json_rpc_response(&response_line)
}

fn parse_json_rpc_response(response_line: &str) -> Result<Value, RpcError> {
    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| RpcError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        let data = err.get("data").cloned();
        return Err(RpcError::DaemonRpc {
            code,
            message,
            data,
        });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{ServerConfig, ServerConnection};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;

    struct TestCa {
        cert_pem: String,
        key_pair: KeyPair,
        cert_for_signing: rcgen::Certificate,
    }

    fn mint_test_ca(common_name: &str) -> TestCa {
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let key_pair = KeyPair::generate().expect("ca keypair");
        let cert_for_signing = params.self_signed(&key_pair).expect("self-signed CA");
        let cert_pem = cert_for_signing.pem();
        TestCa {
            cert_pem,
            key_pair,
            cert_for_signing,
        }
    }

    struct LeafPair {
        cert_pem: String,
        key_pem: String,
    }

    fn mint_leaf_cert(
        ca: &TestCa,
        common_name: &str,
        is_server: bool,
        sans: Vec<String>,
    ) -> LeafPair {
        let mut params = CertificateParams::new(sans).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![if is_server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        let key_pair = KeyPair::generate().expect("leaf keypair");
        let issuer =
            rcgen::Issuer::from_ca_cert_pem(ca.cert_for_signing.pem().as_str(), &ca.key_pair)
                .expect("CA issuer");
        let cert = params
            .signed_by(&key_pair, &issuer)
            .expect("CA-signed leaf");
        LeafPair {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        }
    }

    fn write_bridge_cert_bundle(dir: &std::path::Path, ca: &TestCa, client: &LeafPair) {
        std::fs::write(dir.join("ca.crt"), &ca.cert_pem).expect("write ca");
        std::fs::write(dir.join("client.crt"), &client.cert_pem).expect("write client cert");
        std::fs::write(dir.join("client.key"), &client.key_pem).expect("write client key");
    }

    fn build_server_tls(ca: &TestCa, server: &LeafPair) -> Arc<ServerConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut roots = RootCertStore::empty();
        let mut ca_cursor = std::io::Cursor::new(ca.cert_pem.as_bytes());
        for ca_cert in rustls_pemfile::certs(&mut ca_cursor) {
            let ca_cert = ca_cert.expect("ca cert");
            roots.add(ca_cert).expect("add ca to roots");
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("client verifier");

        let mut cert_cursor = std::io::Cursor::new(server.cert_pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
            .map(|c| c.expect("server cert"))
            .collect();
        let mut key_cursor = std::io::Cursor::new(server.key_pem.as_bytes());
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
            .expect("server key")
            .expect("server key present");
        let key_for_config: PrivateKeyDer<'static> = match key {
            PrivateKeyDer::Pkcs8(k) => {
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()))
            }
            other => other,
        };

        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key_for_config)
            .expect("server tls config");
        Arc::new(config)
    }

    fn spawn_echo_server(config: Arc<ServerConfig>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let conn = ServerConnection::new(config).expect("server connection");
            let tls_stream = StreamOwned::new(conn, tcp);
            let mut reader = BufReader::new(tls_stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("read request");
            let request: Value = serde_json::from_str(request_line.trim()).expect("request json");
            assert_eq!(request.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
            assert_eq!(request.get("method").and_then(Value::as_str), Some("ping"));
            let mut tls_stream = reader.into_inner();
            let mut response =
                serde_json::to_string(&json!({"id":"1","result":{"ok":true}})).expect("response");
            response.push('\n');
            tls_stream
                .write_all(response.as_bytes())
                .expect("write response");
            tls_stream.flush().expect("flush response");
        });
        (format!("https://127.0.0.1:{}", addr.port()), handle)
    }

    /// Process-global env vars are shared state across the test runner's
    /// thread pool. Serialize the env-mutating cases through this mutex
    /// so they don't race each other; combine all set/unset operations
    /// inside the locked region.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(value) => unsafe { std::env::set_var(k, value) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, original) in saved {
            match original {
                Some(value) => unsafe { std::env::set_var(&k, value) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }
    }

    #[test]
    fn decide_transport_returns_uds_when_bridge_url_unset() {
        with_env(
            &[("EMBER_BRIDGE_URL", None), ("EMBER_SOCKET_PATH", None)],
            || {
                let t = decide_transport();
                match t {
                    DaemonTransport::Uds(path) => {
                        assert!(path.ends_with(".ember/run/daemon.sock"));
                    }
                    other => panic!("expected Uds, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn decide_transport_returns_uds_when_bridge_url_empty() {
        with_env(
            &[("EMBER_BRIDGE_URL", Some("")), ("EMBER_SOCKET_PATH", None)],
            || {
                assert!(matches!(decide_transport(), DaemonTransport::Uds(_)));
            },
        );
    }

    #[test]
    fn decide_transport_returns_mtls_tcp_when_bridge_url_set() {
        with_env(
            &[
                (
                    "EMBER_BRIDGE_URL",
                    Some("https://host.docker.internal:4243"),
                ),
                ("EMBER_CLIENT_CERT", None),
                ("EMBER_CLIENT_KEY", None),
                ("EMBER_CA_CERT", None),
                ("EMBER_BRIDGE_CERT_DIR", None),
            ],
            || {
                // construct_runtime_mtls_tcp_transport_decide — checkpoint mirrored
                // in the in-container test body for grep coverage.
                let t = decide_transport();
                match t {
                    DaemonTransport::MtlsTcp {
                        url,
                        server_name,
                        cert_path,
                        key_path,
                        ca_path,
                    } => {
                        assert_eq!(url, "https://host.docker.internal:4243");
                        assert_eq!(server_name, "localhost");
                        assert_eq!(cert_path, PathBuf::from("/run/ember/client.crt"));
                        assert_eq!(key_path, PathBuf::from("/run/ember/client.key"));
                        assert_eq!(ca_path, PathBuf::from("/run/ember/ca.crt"));
                    }
                    other => panic!("expected MtlsTcp, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn decide_transport_honors_bridge_cert_dir_override() {
        with_env(
            &[
                (
                    "EMBER_BRIDGE_URL",
                    Some("https://host.docker.internal:4243"),
                ),
                ("EMBER_BRIDGE_CERT_DIR", Some("/tmp/alt-certs")),
            ],
            || {
                let t = decide_transport();
                match t {
                    DaemonTransport::MtlsTcp {
                        cert_path,
                        key_path,
                        ca_path,
                        ..
                    } => {
                        assert_eq!(cert_path, PathBuf::from("/tmp/alt-certs/client.crt"));
                        assert_eq!(key_path, PathBuf::from("/tmp/alt-certs/client.key"));
                        assert_eq!(ca_path, PathBuf::from("/tmp/alt-certs/ca.crt"));
                    }
                    other => panic!("expected MtlsTcp, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn decide_transport_honors_explicit_bridge_cert_paths_and_server_name() {
        with_env(
            &[
                (
                    "EMBER_BRIDGE_URL",
                    Some("https://host.docker.internal:4243"),
                ),
                ("EMBER_CLIENT_CERT", Some("/tmp/certs/custom-client.crt")),
                ("EMBER_CLIENT_KEY", Some("/tmp/certs/custom-client.key")),
                ("EMBER_CA_CERT", Some("/tmp/certs/custom-ca.crt")),
                ("EMBER_DAEMON_SERVER_NAME", Some("bridge.internal")),
            ],
            || {
                let t = decide_transport();
                match t {
                    DaemonTransport::MtlsTcp {
                        server_name,
                        cert_path,
                        key_path,
                        ca_path,
                        ..
                    } => {
                        assert_eq!(server_name, "bridge.internal");
                        assert_eq!(cert_path, PathBuf::from("/tmp/certs/custom-client.crt"));
                        assert_eq!(key_path, PathBuf::from("/tmp/certs/custom-client.key"));
                        assert_eq!(ca_path, PathBuf::from("/tmp/certs/custom-ca.crt"));
                    }
                    other => panic!("expected MtlsTcp, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn call_daemon_rpc_current_env_uses_mtls_when_bridge_env_present() {
        let ca = mint_test_ca("construct-runtime-bridge-ca");
        let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".to_string()]);
        let client = mint_leaf_cert(&ca, "client", false, Vec::new());
        let tempdir = tempfile::tempdir().expect("tempdir");
        write_bridge_cert_bundle(tempdir.path(), &ca, &client);
        let server_tls = build_server_tls(&ca, &server);
        let (bridge_url, server_thread) = spawn_echo_server(server_tls);
        let client_cert = tempdir
            .path()
            .join("client.crt")
            .to_string_lossy()
            .into_owned();
        let client_key = tempdir
            .path()
            .join("client.key")
            .to_string_lossy()
            .into_owned();
        let ca_cert = tempdir.path().join("ca.crt").to_string_lossy().into_owned();

        with_env(
            &[
                ("EMBER_BRIDGE_URL", Some(&bridge_url)),
                ("EMBER_CLIENT_CERT", Some(&client_cert)),
                ("EMBER_CLIENT_KEY", Some(&client_key)),
                ("EMBER_CA_CERT", Some(&ca_cert)),
                ("EMBER_DAEMON_SERVER_NAME", Some("localhost")),
                ("EMBER_SOCKET_PATH", None),
            ],
            || {
                let response =
                    call_daemon_rpc_current_env("ping", &json!({"probe":"mtls"})).expect("rpc");
                assert_eq!(response, json!({"ok": true}));
            },
        );

        server_thread.join().expect("server thread");
    }

    #[test]
    fn daemon_socket_path_honors_ember_socket_path_override() {
        with_env(
            &[("EMBER_SOCKET_PATH", Some("/tmp/test-daemon.sock"))],
            || {
                assert_eq!(daemon_socket_path(), PathBuf::from("/tmp/test-daemon.sock"));
            },
        );
    }

    #[test]
    fn daemon_unavailable_message_explains_missing_bridge_wiring_for_container_socket() {
        with_env(&[("EMBER_BRIDGE_URL", None)], || {
            let msg = format_daemon_unavailable(
                Path::new("/run/emberd-host/daemon.sock"),
                &std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            );
            assert!(msg.contains("EMBER_BRIDGE_URL plus client cert wiring"));
        });
    }
}
