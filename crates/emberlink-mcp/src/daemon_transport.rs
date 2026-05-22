use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// In-container mTLS bridge transport configuration. Per design component 1,
/// the in-container `emberlink-mcp` server dials the host's ember-rpc
/// listener (per-agent client cert mounted at
/// `/run/ember/client-cert/{client.crt,client.key,ca.crt}`).
///
/// `ca.crt` is the SOLE trust anchor — system roots are deliberately NEVER
/// consulted, mirroring the server-side invariant in
/// `crates/ember-rpc/src/listener.rs::build_server_tls_config`.
#[derive(Clone)]
pub struct MtlsBridgeConfig {
    /// `host:port` string the orchestrator publishes via `EMBER_DAEMON_ENDPOINT`.
    /// macOS Docker Desktop: `host.docker.internal:4243`. Linux Docker:
    /// the host's container-network gateway IP plus the listener port.
    pub endpoint: String,
    /// Pre-built TLS config holding the per-agent client cert + the bridge CA
    /// as the sole root.
    pub tls_config: Arc<ClientConfig>,
    /// SNI / server-name presented during the TLS handshake. ember-rpc's
    /// server cert is minted with a stable SAN; the client side validates
    /// against this name. Defaults to `localhost` for parity with the
    /// listener smoke tests.
    pub server_name: String,
}

impl std::fmt::Debug for MtlsBridgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately do NOT print the inner `Arc<ClientConfig>` — it
        // holds key material whose Debug shape isn't audited. Mirrors the
        // [redacted] convention enforced in the listener's error paths.
        f.debug_struct("MtlsBridgeConfig")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("tls_config", &"[redacted]")
            .finish()
    }
}

/// Transport kind discriminator. Selected at construction time by the
/// caller (`main.rs` chooses based on `EMBER_DAEMON_ENDPOINT`).
///
/// Both variants present the same external surface via [`DaemonTransport::
/// call_tool`]; the variant only changes the wire under the JSON-RPC frame.
enum Transport {
    /// Legacy UDS path used by host-mode emberlink-mcp callers. Sync I/O.
    UnixSocket(PathBuf),
    /// mTLS+TCP path used by in-container callers (design component 1).
    /// Owns a dedicated tokio runtime so sync `DaemonClient` trait methods
    /// can `block_on` the async TLS round-trip even when called from
    /// within `main.rs`'s `current_thread` runtime.
    Mtls {
        config: MtlsBridgeConfig,
        runtime: Arc<tokio::runtime::Runtime>,
    },
}

/// MCP transport that routes tool calls through the ember daemon — either
/// a host-mode UDS or the design in-container mTLS bridge.
pub struct DaemonTransport {
    inner: Transport,
}

impl DaemonTransport {
    /// Build a transport that talks to the daemon over a Unix domain socket.
    /// This is the host-mode default and keeps backward compatibility for
    /// existing callers (tests + sequential dev environments).
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            inner: Transport::UnixSocket(socket_path.as_ref().to_path_buf()),
        }
    }

    /// Build a transport that talks to the daemon over the mTLS bridge.
    /// `runtime` is the dedicated multi-thread runtime used for the
    /// underlying tokio TLS I/O. Anchor:
    /// `emberlink_mcp_mtls_client_handshake`.
    pub fn new_mtls(config: MtlsBridgeConfig, runtime: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            inner: Transport::Mtls { config, runtime },
        }
    }

    /// Returns `Some(path)` for UDS transports, `None` for mTLS.
    ///
    /// Kept as an `Option` rather than panicking so the legacy
    /// `socket_path()` callers in `main.rs` / `lib.rs` (which use it to
    /// build the receipt-transport socket) can gracefully fall back when
    /// running in container mode. The mTLS branch in `McpServer::
    /// with_daemon_socket` is unused in container mode — observability
    /// tools route through `call_tool` regardless of variant.
    pub fn socket_path(&self) -> &std::path::Path {
        match &self.inner {
            Transport::UnixSocket(p) => p.as_path(),
            // For mTLS, return a checkpoint path. Callers that genuinely
            // need a UDS path are host-mode by construction and never
            // see this branch; the path is non-empty so `Path::display()`
            // produces something useful in error messages if a caller
            // does hit it.
            Transport::Mtls { .. } => Path::new("/run/ember/mtls-bridge"),
        }
    }

    /// Returns `true` when the transport routes through the mTLS bridge
    /// rather than a host UDS. Used by unit tests to assert the
    /// `EMBER_DAEMON_ENDPOINT` selector wired the expected variant.
    pub fn is_mtls(&self) -> bool {
        matches!(self.inner, Transport::Mtls { .. })
    }

    /// Map MCP tool name to daemon socket method name.
    ///
    /// Note: `request_grant` is intentionally NOT in this map. It is
    /// handled by a special-case branch in [`Self::call_tool`] that routes
    /// it through `request_access` so the policy engine and pre-eval rate
    /// limiter both run. See design and TODO 69.1.
    fn map_tool_to_method(tool_name: &str) -> Option<&str> {
        match tool_name {
            // Credential access
            "use_credential" => Some("use_credential"),
            "list_grants" => Some("list_grants"),
            "grant_status" => Some("evaluate_grant"),
            "revoke_grant" => Some("revoke_grant"),
            "delegate_grant" => Some("delegate_grant"),
            "grant_summary" => Some("grant_summary"),
            // Persona management
            "whoami" => Some("list_personas"),
            "create_persona" => Some("create_persona"),
            // Approval workflow
            "request_access" => Some("request_access"),
            "list_approvals" => Some("list_pending_approvals"),
            "submit_approval" => Some("submit_approval"),
            // Observability
            "audit_query" => Some("audit_query"),
            "detect_anomalies" => Some("detect_anomalies"),
            // Receipts (Stream D)
            "list_receipts" => Some("list_receipts"),
            "get_receipt" => Some("get_receipt"),
            "daemon_persona" => Some("daemon_persona"),
            // Budget status (P69K-F1)
            "grant_budget_status" => Some("grant_budget_status"),
            // Vault
            "vault_list" => Some("vault_list"),
            // Health
            "ping" => Some("ping"),
            _ => None,
        }
    }

    /// Extract the host component from a string that may be a URL or a bare
    /// hostname/path. Returns `None` if the string is clearly not URL-like.
    ///
    /// Parsing strategy (no added deps):
    /// 1. If the string contains `://`, split on `://` and take the authority
    ///    portion (everything before the first `/` after the scheme).
    /// 2. Otherwise, take the portion before the first `/` — bare hostnames
    ///    like `api.github.com` or paths like `api.github.com/repos/...`.
    /// 3. Strip any `user@` prefix and `:port` suffix.
    /// 4. Return `None` for empty results or strings that look like simple
    ///    credential names (no `.` and no `/`).
    fn extract_host(s: &str) -> Option<String> {
        let authority = if let Some(after_scheme) = s.split("://").nth(1) {
            after_scheme.split('/').next().unwrap_or("")
        } else {
            s.split('/').next().unwrap_or("")
        };
        // Strip user@ prefix and :port suffix.
        let host_port = authority.split('@').next_back().unwrap_or(authority);
        let host = host_port.split(':').next().unwrap_or(host_port);
        // Reject empty or plain words with no structure (looks like a
        // credential name, not a hostname).
        if host.is_empty() || (!host.contains('.') && !host.contains(':')) {
            return None;
        }
        Some(host.to_string())
    }

    /// Translate a `request_grant` MCP call into `request_access` daemon
    /// parameters by synthesizing the `action` field from `credential_name`.
    ///
    /// This ensures agent-initiated credential requests route through the
    /// policy engine AND the pre-evaluation rate limiter (see TODO 69.1).
    /// All other fields are forwarded unchanged — no parameter tampering.
    ///
    /// Also injects NOTIF-1 banner fields (`tool_name`, `target_host`,
    /// `target_url`, `agent_framework`) so the approval banner in the
    /// daemon shows richer context for MCP-originated requests.
    ///
    /// Fails closed: returns `Protocol` error if `credential_name` is
    /// missing rather than silently passing an empty action string.
    fn translate_request_grant(
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        let credential_name = arguments
            .get("credential_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DaemonTransportError::Protocol(
                    "missing credential_name for request_grant".to_string(),
                )
            })?;

        let action = format!("credential.access.{credential_name}");

        // Clone the caller's arguments and add the synthesized action.
        // If `action` was already supplied by the caller, the synthesized
        // value overrides it to prevent callers from bypassing the naming
        // convention the policy engine expects.
        let mut augmented = match arguments {
            serde_json::Value::Object(_) => arguments.clone(),
            _ => serde_json::Value::Object(serde_json::Map::new()),
        };
        if let Some(obj) = augmented.as_object_mut() {
            obj.insert("action".to_string(), serde_json::Value::String(action));

            // NOTIF-1: inject banner fields for the daemon's approval
            // notification. These are set only when not already present so
            // callers that supply richer context aren't overwritten.
            obj.entry("tool_name")
                .or_insert_with(|| serde_json::Value::String("mcp/request_grant".to_string()));
            obj.entry("agent_framework")
                .or_insert_with(|| serde_json::Value::String("mcp".to_string()));

            // Derive target_host from `resource_id` when present. This field
            // often carries a URL-like path (e.g. "api.github.com/repos/...").
            // Fall back to `credential_name` if `resource_id` is absent.
            let url_candidate = arguments
                .get("resource_id")
                .and_then(|v| v.as_str())
                .or(Some(credential_name));
            if let Some(host) = url_candidate.and_then(Self::extract_host) {
                obj.entry("target_host")
                    .or_insert_with(|| serde_json::Value::String(host.clone()));
                obj.entry("target_url")
                    .or_insert_with(|| serde_json::Value::String(host));
            }
        }
        Ok(augmented)
    }

    /// Execute an MCP tool call by routing through the daemon.
    pub fn call_tool(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        // Special case: `request_grant` routes through `request_access` so
        // policy evaluation AND the pre-eval rate limiter both apply.
        // TODO 69.1 / design. `translated` owns the augmented params so a
        // borrow survives the rest of the call.
        let translated: Option<serde_json::Value> = if tool_name == "request_grant" {
            Some(Self::translate_request_grant(arguments)?)
        } else {
            None
        };
        let (method, params_ref): (&str, &serde_json::Value) = if tool_name == "request_grant" {
            (
                "request_access",
                translated.as_ref().expect("translated set above"),
            )
        } else {
            let m = Self::map_tool_to_method(tool_name)
                .ok_or_else(|| DaemonTransportError::UnknownTool(tool_name.to_string()))?;
            (m, arguments)
        };

        self.call_raw(method, params_ref)
    }

    /// Call a daemon JSON-RPC method by name, bypassing the MCP tool→method
    /// map. Used by the agent runtime adapter (`DaemonTransportClient` in
    /// the emberlink-mcp binary's main module) where the tool layer's
    /// renamings don't apply, and by the
    /// `bridge.cert_expiring_soon` timer task to post the warning.
    pub fn call_raw(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        // Build request once; both transports send the same JSON-RPC wire shape.
        let request = serde_json::json!({
            "id": "1",
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&request)
            .map_err(|e| DaemonTransportError::Protocol(e.to_string()))?;
        line.push('\n');

        let response_line = match &self.inner {
            Transport::UnixSocket(socket_path) => Self::uds_round_trip(socket_path, &line)?,
            Transport::Mtls { config, runtime } => {
                // emberlink_mcp_mtls_client_handshake — the in-container
                // bridge transport presents the per-agent client cert on
                // every connect (design component 1). The handshake
                // happens here on every `call_raw`; rustls reuses session
                // tickets where possible but each connect is a fresh
                // round-trip per the brief's "every connect presents the
                // client cert" acceptance criterion.
                Self::mtls_round_trip(config, runtime, &line)?
            }
        };

        let response: serde_json::Value = serde_json::from_str(response_line.trim())
            .map_err(|e| DaemonTransportError::Protocol(e.to_string()))?;

        if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(DaemonTransportError::DaemonError(msg.to_string()));
        }

        Ok(response
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Sync UDS round-trip — newline-delimited JSON-RPC request/response.
    /// Extracted as a free associated function so the variant dispatch in
    /// [`Self::call_tool`] reads as a simple match.
    fn uds_round_trip(
        socket_path: &Path,
        request_line: &str,
    ) -> Result<String, DaemonTransportError> {
        use std::io::{BufRead, BufReader, Write};

        let stream = std::os::unix::net::UnixStream::connect(socket_path)
            .map_err(DaemonTransportError::Io)?;
        let mut writer = stream.try_clone().map_err(DaemonTransportError::Io)?;
        let mut reader = BufReader::new(stream);

        writer
            .write_all(request_line.as_bytes())
            .map_err(DaemonTransportError::Io)?;

        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(DaemonTransportError::Io)?;
        Ok(response_line)
    }

    /// Synchronous mTLS round-trip. Blocks the caller on the bridge
    /// transport's dedicated runtime so sync `DaemonClient` trait methods
    /// (called from `main.rs`'s `current_thread` runtime) don't trigger
    /// the "blocking on async runtime" panic.
    fn mtls_round_trip(
        config: &MtlsBridgeConfig,
        runtime: &Arc<tokio::runtime::Runtime>,
        request_line: &str,
    ) -> Result<String, DaemonTransportError> {
        let request = request_line.to_owned();
        let endpoint = config.endpoint.clone();
        let server_name_str = config.server_name.clone();
        let tls_config = Arc::clone(&config.tls_config);
        runtime.block_on(async move {
            let server_name = ServerName::try_from(server_name_str)
                .map_err(|e| DaemonTransportError::Protocol(format!("invalid server_name: {e}")))?;
            let tcp = TcpStream::connect(&endpoint)
                .await
                .map_err(DaemonTransportError::Io)?;
            let connector = TlsConnector::from(tls_config);
            let mut tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(DaemonTransportError::Io)?;
            tls_stream
                .write_all(request.as_bytes())
                .await
                .map_err(DaemonTransportError::Io)?;
            tls_stream.flush().await.map_err(DaemonTransportError::Io)?;

            let mut reader = AsyncBufReader::new(tls_stream);
            let mut response_line = String::new();
            reader
                .read_line(&mut response_line)
                .await
                .map_err(DaemonTransportError::Io)?;
            Ok::<String, DaemonTransportError>(response_line)
        })
    }
}

// ---------------------------------------------------------------------------
// Bridge-cert loader
// ---------------------------------------------------------------------------

/// Errors raised when loading the in-container bridge client cert+key+CA.
///
/// Distinct from [`DaemonTransportError`] because cert-loading happens at
/// startup before any RPC traffic; the caller (`main.rs`) treats every
/// variant here as fail-closed (exit non-zero). Spelled out as discrete
/// variants so the startup error message tells the operator which of the
/// three files is missing/malformed.
#[derive(Debug)]
pub enum BridgeCertError {
    ReadCert(PathBuf, std::io::Error),
    ReadKey(PathBuf, std::io::Error),
    ReadCa(PathBuf, std::io::Error),
    ParseCert(PathBuf, String),
    ParseKey(PathBuf, String),
    ParseCa(PathBuf, String),
    EmptyCert(PathBuf),
    EmptyKey(PathBuf),
    EmptyCa(PathBuf),
    TlsConfig(String),
}

impl std::fmt::Display for BridgeCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadCert(p, e) => write!(f, "read client cert {}: {e}", p.display()),
            Self::ReadKey(p, e) => write!(f, "read client key {}: {e}", p.display()),
            Self::ReadCa(p, e) => write!(f, "read CA cert {}: {e}", p.display()),
            Self::ParseCert(p, e) => write!(f, "parse client cert {}: {e}", p.display()),
            Self::ParseKey(p, e) => write!(f, "parse client key {}: {e}", p.display()),
            Self::ParseCa(p, e) => write!(f, "parse CA cert {}: {e}", p.display()),
            Self::EmptyCert(p) => {
                write!(f, "client cert {} contained no certificates", p.display())
            }
            Self::EmptyKey(p) => write!(f, "client key {} contained no private key", p.display()),
            Self::EmptyCa(p) => write!(f, "CA cert {} contained no certificates", p.display()),
            Self::TlsConfig(s) => write!(f, "build TLS config: {s}"),
        }
    }
}

impl std::error::Error for BridgeCertError {}

/// Default in-container path for the per-agent client cert bundle. The
/// orchestrator's spawn flow mounts these into the container at this
/// path (implementation-note-26). Overridable via
/// `EMBER_BRIDGE_CERT_DIR` for tests + alternate deployment shapes.
pub const DEFAULT_BRIDGE_CERT_DIR: &str = "/run/ember/client-cert";

/// Cert + key + CA loaded off disk. Returned by [`load_bridge_cert_files`]
/// so the startup path can (a) build the [`ClientConfig`] and (b) feed
/// the raw cert DER into the expiry-timer scheduler.
///
/// `Debug` is hand-implemented to redact the private key — `PrivateKeyDer`
/// itself prints its variant tag but not key bytes, but the project
/// convention is "never let key material near a `Debug` line" (see
/// `MtlsBridgeConfig::Debug` for the same convention).
pub struct LoadedBridgeCert {
    pub client_certs: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub ca_certs: Vec<CertificateDer<'static>>,
}

impl std::fmt::Debug for LoadedBridgeCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedBridgeCert")
            .field("client_certs_len", &self.client_certs.len())
            .field("client_key", &"[redacted]")
            .field("ca_certs_len", &self.ca_certs.len())
            .finish()
    }
}

/// Resolve the cert directory: env-var override wins, otherwise the
/// canonical in-container path. Pure function — no I/O.
pub fn resolve_bridge_cert_dir() -> PathBuf {
    std::env::var_os("EMBER_BRIDGE_CERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BRIDGE_CERT_DIR))
}

/// Read + parse the three PEM files. Fails closed on any missing or
/// malformed file — the caller (`main.rs`) exits non-zero on Err so the
/// container doesn't silently fall through to an anonymous-client lane.
pub fn load_bridge_cert_files(dir: &Path) -> Result<LoadedBridgeCert, BridgeCertError> {
    let cert_path = dir.join("client.crt");
    let key_path = dir.join("client.key");
    let ca_path = dir.join("ca.crt");

    let cert_bytes =
        std::fs::read(&cert_path).map_err(|e| BridgeCertError::ReadCert(cert_path.clone(), e))?;
    let key_bytes =
        std::fs::read(&key_path).map_err(|e| BridgeCertError::ReadKey(key_path.clone(), e))?;
    let ca_bytes =
        std::fs::read(&ca_path).map_err(|e| BridgeCertError::ReadCa(ca_path.clone(), e))?;

    let client_certs: Vec<CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(cert_bytes);
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BridgeCertError::ParseCert(cert_path.clone(), e.to_string()))?
    };
    if client_certs.is_empty() {
        return Err(BridgeCertError::EmptyCert(cert_path));
    }

    let client_key: PrivateKeyDer<'static> = {
        let mut cursor = std::io::Cursor::new(key_bytes);
        rustls_pemfile::private_key(&mut cursor)
            .map_err(|e| BridgeCertError::ParseKey(key_path.clone(), e.to_string()))?
            .ok_or_else(|| BridgeCertError::EmptyKey(key_path.clone()))?
    };

    let ca_certs: Vec<CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(ca_bytes);
        rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| BridgeCertError::ParseCa(ca_path.clone(), e.to_string()))?
    };
    if ca_certs.is_empty() {
        return Err(BridgeCertError::EmptyCa(ca_path));
    }

    Ok(LoadedBridgeCert {
        client_certs,
        client_key,
        ca_certs,
    })
}

/// Build the per-connection `rustls::ClientConfig` from a [`LoadedBridgeCert`].
///
/// Security invariants — mirror the server-side
/// `crates/ember-rpc/src/listener.rs::build_server_tls_config` shape:
///
/// - `RootCertStore` is built FRESH and contains ONLY the bridge CA.
///   System roots are NEVER consulted. Closed trust domain per design.
/// - `with_client_auth_cert` REQUIRES a client cert; the daemon-side
///   `WebPkiClientVerifier` refuses anonymous connections.
pub fn build_client_tls_config(
    loaded: LoadedBridgeCert,
) -> Result<Arc<ClientConfig>, BridgeCertError> {
    // Install ring as the default crypto provider if not already done.
    // Idempotent — Err means a provider was already installed elsewhere
    // in the process (e.g. a test harness).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = RootCertStore::empty();
    for ca in loaded.ca_certs {
        root_store
            .add(ca)
            .map_err(|e| BridgeCertError::TlsConfig(format!("add CA to root store: {e}")))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(loaded.client_certs, loaded.client_key)
        .map_err(|e| BridgeCertError::TlsConfig(format!("with_client_auth_cert: {e}")))?;
    Ok(Arc::new(config))
}

#[derive(Debug)]
pub enum DaemonTransportError {
    Io(std::io::Error),
    Protocol(String),
    DaemonError(String),
    UnknownTool(String),
}

impl std::fmt::Display for DaemonTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
            Self::DaemonError(s) => write!(f, "daemon error: {s}"),
            Self::UnknownTool(s) => write!(f, "unknown tool: {s}"),
        }
    }
}

impl std::error::Error for DaemonTransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_tool_to_method_credential_tools() {
        // `request_grant` is intentionally NOT in the static map. It is
        // handled by a special-case branch in `call_tool` that routes it
        // through `request_access` so the policy engine and pre-eval rate
        // limiter both apply. See TODO 69.1.
        assert_eq!(DaemonTransport::map_tool_to_method("request_grant"), None);
        assert_eq!(
            DaemonTransport::map_tool_to_method("use_credential"),
            Some("use_credential")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("list_grants"),
            Some("list_grants")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("grant_status"),
            Some("evaluate_grant")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("revoke_grant"),
            Some("revoke_grant")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("delegate_grant"),
            Some("delegate_grant")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("grant_summary"),
            Some("grant_summary")
        );
    }

    #[test]
    fn translate_request_grant_synthesizes_action() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "scope": "repo:read",
            "ttl_secs": 3600
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert_eq!(translated["action"], "credential.access.github-token");
        // Other fields must be forwarded unchanged (no parameter tampering).
        assert_eq!(translated["persona_id"], "persona-abc");
        assert_eq!(translated["credential_name"], "github-token");
        assert_eq!(translated["scope"], "repo:read");
        assert_eq!(translated["ttl_secs"], 3600);
    }

    #[test]
    fn translate_request_grant_missing_credential_name_fails_closed() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "scope": "repo:read",
        });
        let err = DaemonTransport::translate_request_grant(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => {
                assert!(msg.contains("credential_name"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn translate_request_grant_overrides_caller_supplied_action() {
        // A caller cannot bypass the policy naming convention by supplying
        // their own `action` — the synthesized value wins.
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "scope": "repo:read",
            "action": "credential.access.something-else"
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert_eq!(translated["action"], "credential.access.github-token");
    }

    #[test]
    fn translate_request_grant_non_object_fails_closed() {
        let args = serde_json::json!("not-an-object");
        let err = DaemonTransport::translate_request_grant(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => {
                assert!(msg.contains("credential_name"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn map_tool_to_method_persona_tools() {
        assert_eq!(
            DaemonTransport::map_tool_to_method("whoami"),
            Some("list_personas")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("create_persona"),
            Some("create_persona")
        );
    }

    #[test]
    fn map_tool_to_method_approval_tools() {
        assert_eq!(
            DaemonTransport::map_tool_to_method("request_access"),
            Some("request_access")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("list_approvals"),
            Some("list_pending_approvals")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("submit_approval"),
            Some("submit_approval")
        );
    }

    #[test]
    fn map_tool_to_method_observability_tools() {
        assert_eq!(
            DaemonTransport::map_tool_to_method("audit_query"),
            Some("audit_query")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("detect_anomalies"),
            Some("detect_anomalies")
        );
    }

    #[test]
    fn map_tool_to_method_vault_and_health_tools() {
        assert_eq!(
            DaemonTransport::map_tool_to_method("vault_list"),
            Some("vault_list")
        );
        assert_eq!(DaemonTransport::map_tool_to_method("ping"), Some("ping"));
    }

    #[test]
    fn map_tool_to_method_grant_budget_status_routes_to_daemon() {
        // `grant_budget_status` is a read-only observability tool that bypasses
        // the agent runtime and talks directly to the daemon socket — mirrors
        // the `list_receipts` / `get_receipt` pattern.
        assert_eq!(
            DaemonTransport::map_tool_to_method("grant_budget_status"),
            Some("grant_budget_status")
        );
    }

    #[test]
    fn map_tool_to_method_unknown_returns_none() {
        assert_eq!(DaemonTransport::map_tool_to_method("nonexistent"), None);
        assert_eq!(DaemonTransport::map_tool_to_method(""), None);
        assert_eq!(DaemonTransport::map_tool_to_method("WHOAMI"), None);
    }

    #[test]
    fn error_display_io() {
        let e = DaemonTransportError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no socket",
        ));
        assert!(e.to_string().starts_with("I/O error:"));
    }

    #[test]
    fn error_display_protocol() {
        let e = DaemonTransportError::Protocol("bad json".to_string());
        assert_eq!(e.to_string(), "protocol error: bad json");
    }

    #[test]
    fn error_display_daemon_error() {
        let e = DaemonTransportError::DaemonError("not authorized".to_string());
        assert_eq!(e.to_string(), "daemon error: not authorized");
    }

    #[test]
    fn error_display_unknown_tool() {
        let e = DaemonTransportError::UnknownTool("foo".to_string());
        assert_eq!(e.to_string(), "unknown tool: foo");
    }

    // --- NOTIF-1: MCP approval-request banner fields ---

    #[test]
    fn mcp_approval_request_populates_tool_fields() {
        // request_grant with a URL-like resource_id should populate
        // tool_name and target_host in the translated params so the
        // daemon's approval banner shows richer context.
        let args = serde_json::json!({
            "credential_name": "github-token",
            "resource_id": "api.github.com/repos/emberdotlink/emberlink",
            "scope": "repo:push",
            "ttl_secs": 3600
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert!(
            translated["tool_name"]
                .as_str()
                .map(|s| s.starts_with("mcp"))
                .unwrap_or(false),
            "tool_name should start with 'mcp', got: {:?}",
            translated["tool_name"]
        );
        assert!(
            translated["target_host"].is_string(),
            "target_host should be present when resource_id contains a hostname"
        );
        assert_eq!(
            translated["target_host"].as_str(),
            Some("api.github.com"),
            "target_host should be the authority portion of resource_id"
        );
        assert_eq!(translated["agent_framework"], "mcp");
    }

    #[test]
    fn mcp_approval_request_no_resource_id_falls_back_to_credential_name() {
        // When resource_id is absent, the host extraction falls back to
        // credential_name. A plain name like "github-token" has no dot so
        // target_host stays None — that's expected and correct.
        let args = serde_json::json!({
            "credential_name": "github-token",
            "scope": "repo:read"
        });
        let translated = DaemonTransport::translate_request_grant(&args).unwrap();
        assert_eq!(translated["tool_name"], "mcp/request_grant");
        assert_eq!(translated["agent_framework"], "mcp");
        // Plain credential name has no dot → no host extracted.
        assert!(
            translated.get("target_host").is_none() || translated["target_host"].is_null(),
            "plain credential name should not produce a target_host"
        );
    }

    #[test]
    fn extract_host_url_with_scheme() {
        assert_eq!(
            DaemonTransport::extract_host("https://api.github.com/repos/foo"),
            Some("api.github.com".to_string())
        );
    }

    #[test]
    fn extract_host_bare_path() {
        assert_eq!(
            DaemonTransport::extract_host("api.github.com/repos/foo"),
            Some("api.github.com".to_string())
        );
    }

    #[test]
    fn extract_host_plain_name_returns_none() {
        assert_eq!(DaemonTransport::extract_host("github-token"), None);
        assert_eq!(DaemonTransport::extract_host("my_credential"), None);
    }

    #[test]
    fn extract_host_strips_port() {
        assert_eq!(
            DaemonTransport::extract_host("https://api.example.com:8443/path"),
            Some("api.example.com".to_string())
        );
    }
}
