use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// In-container mTLS bridge transport configuration. Per ADR 154 component 1,
/// the in-container `emberlink-mcp` server dials the host's ember-rpc
/// listener (per-agent client cert mounted at
/// `/run/ember/client-cert/{client.crt,client.key,ca.crt}`).
///
/// `ca.crt` is the SOLE trust anchor — system roots are deliberately NEVER
/// consulted, mirroring the server-side invariant in
/// `crates/ember-rpc/src/listener.rs::build_server_tls_config`.
///
/// `tls_config` is wrapped in `Arc<RwLock<Arc<ClientConfig>>>` so the
/// META-AP-EMBERLINK-MCP-CERT-SWAP refresh path can hot-swap the underlying
/// `ClientConfig` (refreshed per-agent cert + key) and have every
/// `DaemonTransport` clone that shares this `MtlsBridgeConfig` observe the
/// new config on its next RPC. Anchor: `emberlink_mcp_cert_swap_landed`.
///
/// Under v0.3.0's per-RPC connect-then-close pattern (find via
/// `per_rpc_connect_then_close_pattern` checkpoint below), cert swap is
/// trivial: write new cert+key into the lock; the next `call_raw` opens a
/// fresh TCP+TLS connection and presents the new cert; the previous RPC's
/// connection was already closed. No connection pool drain semantics
/// required — ADR 173 §Component 4.
#[derive(Clone)]
pub struct MtlsBridgeConfig {
    /// `host:port` string the orchestrator publishes via `EMBER_DAEMON_ENDPOINT`.
    /// macOS Docker Desktop: `host.docker.internal:4243`. Linux Docker:
    /// the host's container-network gateway IP plus the listener port.
    pub endpoint: String,
    /// Pre-built TLS config holding the per-agent client cert + the bridge CA
    /// as the sole root. Wrapped in `Arc<RwLock<Arc<ClientConfig>>>` so the
    /// cert-refresh path can hot-swap it via
    /// [`MtlsBridgeConfig::swap_client_config`] without rebuilding the
    /// surrounding transport or re-handshaking in-flight connections.
    pub tls_config: Arc<RwLock<Arc<ClientConfig>>>,
    /// SNI / server-name presented during the TLS handshake. ember-rpc's
    /// server cert is minted with a stable SAN; the client side validates
    /// against this name. Defaults to `localhost` for parity with the
    /// listener smoke tests.
    pub server_name: String,
    /// Shared "refresh has been failing past the 90% band" flag. Set to
    /// `true` by the refresh client (see `cert_expiry.rs`) at the 90%
    /// band when no successful refresh has landed; gates NEW tool calls
    /// via [`DaemonTransport::call_tool`] with a typed `RefreshFailing`
    /// error. In-flight RPCs are NOT interrupted — ADR 173 §Component 5
    /// "Soft fail-closed at 90% TTL". Anchor:
    /// `emberlink_mcp_cert_refresh_client_landed`.
    ///
    /// `None` for host-mode (UDS) configs and for tests that don't wire
    /// the refresh client; in those cases `call_tool` never refuses.
    pub refresh_failing: Arc<AtomicBool>,
}

impl MtlsBridgeConfig {
    /// Build a `MtlsBridgeConfig` from a plain `Arc<ClientConfig>`. The
    /// outer `Arc<RwLock<...>>` wrapper is constructed here so callers
    /// don't have to know the swap-substrate shape. The `refresh_failing`
    /// flag is initialized `false`; the refresh client (see
    /// `cert_expiry.rs`) flips it at the 90% band when no successful
    /// refresh has landed yet.
    pub fn new(endpoint: String, tls_config: Arc<ClientConfig>, server_name: String) -> Self {
        Self {
            endpoint,
            tls_config: Arc::new(RwLock::new(tls_config)),
            server_name,
            refresh_failing: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark the bridge as refresh-failing (90% band reached with no
    /// successful refresh). Subsequent `call_tool` invocations refuse
    /// with the typed [`DaemonTransportError::RefreshFailing`] error.
    /// Cleared on the next successful refresh.
    pub fn set_refresh_failing(&self, failing: bool) {
        self.refresh_failing.store(failing, Ordering::SeqCst);
    }

    /// Cheap read of the refresh-failing flag. `false` for host-mode
    /// (UDS) configs and for tests that don't wire the refresh client.
    pub fn is_refresh_failing(&self) -> bool {
        self.refresh_failing.load(Ordering::SeqCst)
    }

    /// Atomically replace the inner `Arc<ClientConfig>` with `new_config`.
    /// Every `MtlsBridgeConfig` clone that shares the outer
    /// `Arc<RwLock<...>>` observes the swap on its next RPC; in-flight
    /// connections that already captured the old `Arc<ClientConfig>`
    /// snapshot finish on the old cert (per ADR 173 §Component 4
    /// "no in-flight RPC interruption"). Anchor:
    /// `emberlink_mcp_cert_swap_landed` — searchable anchor for the
    /// M7 cert-swap acceptance criterion.
    ///
    /// Panics only if the lock is poisoned (a prior write panic'd while
    /// holding the lock). The bridge transport never panics under normal
    /// operation, so a poisoned lock is a bug-not-runtime condition; we
    /// surface it loudly rather than papering over it.
    pub fn swap_client_config(&self, new_config: Arc<ClientConfig>) {
        // emberlink_mcp_cert_swap_landed — the rustls ClientConfig swap
        // point for the ADR 173 cert-refresh chain (M7). Atomically
        // replaces the inner Arc; readers see the old value until they
        // re-read the lock on the next call.
        let mut guard = self
            .tls_config
            .write()
            .expect("MtlsBridgeConfig::tls_config lock poisoned");
        *guard = new_config;
    }

    /// Snapshot the current `Arc<ClientConfig>` for a single RPC. Returns
    /// a cheap `Arc` clone so the read-lock guard never crosses an
    /// `.await` point — which would otherwise leak a `!Send` guard into
    /// the tokio task. Used by [`DaemonTransport::mtls_round_trip`].
    pub fn current_client_config(&self) -> Arc<ClientConfig> {
        let guard = self
            .tls_config
            .read()
            .expect("MtlsBridgeConfig::tls_config lock poisoned");
        Arc::clone(&*guard)
    }
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
    /// Host UDS path used by host-mode emberlink-mcp callers. Sync I/O.
    UnixSocket(PathBuf),
    /// mTLS+TCP path used by in-container callers (ADR 154 component 1).
    /// Owns a dedicated tokio runtime so synchronous MCP tool calls can
    /// block on the async TLS round-trip from `main.rs`'s current-thread
    /// runtime without nested-runtime panics.
    Mtls {
        config: MtlsBridgeConfig,
        runtime: Arc<tokio::runtime::Runtime>,
    },
}

/// MCP transport that routes tool calls through the ember daemon — either
/// a host-mode UDS or the ADR 154 in-container mTLS bridge.
pub struct DaemonTransport {
    inner: Transport,
}

impl DaemonTransport {
    /// Build a transport that talks to the daemon over a Unix domain socket.
    /// This is the host-mode default.
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

    /// Returns the UDS path for host transports and a stable checkpoint path for
    /// mTLS transports. Host-only test helpers use this to open raw UDS calls.
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
    /// `EMBER_BRIDGE_URL` selector wired the expected variant.
    pub fn is_mtls(&self) -> bool {
        matches!(self.inner, Transport::Mtls { .. })
    }

    /// Map MCP tool name to daemon socket method name.
    ///
    fn map_tool_to_method(tool_name: &str) -> Option<&str> {
        match tool_name {
            // Canonical MCP control surface (ADR 183/184/187/205 aligned).
            "session.describe" => Some("describe_runtime_attach_target"),
            "catalog.search_actions" => Some("catalog.search_actions"),
            "access.request" => Some("request_access"),
            "grant.list" => Some("list_grants"),
            "status.get" => Some("status"),
            "evidence.query" => Some("receipt_query"),
            "evidence.get" => Some("get_receipt"),
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

    /// Translate the canonical MCP `access.request` surface into the daemon's
    /// `request_access` receiver shape.
    ///
    /// The MCP caller names a package-scoped `action_ref` plus either
    /// `resource_id` or a typed `target`. The daemon resolves authority need
    /// from the Action Manifest; this adapter only adds MCP attribution fields.
    fn translate_access_request(
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        let mut augmented = arguments.as_object().cloned().ok_or_else(|| {
            DaemonTransportError::Protocol(
                "access.request arguments must be a JSON object".to_string(),
            )
        })?;

        if augmented.get("action").is_some() {
            return Err(DaemonTransportError::Protocol(
                "access.request no longer accepts action; use action_ref".to_string(),
            ));
        }
        if augmented.get("scope").is_some() {
            return Err(DaemonTransportError::Protocol(
                "access.request no longer accepts scope; use resource_id or typed target"
                    .to_string(),
            ));
        }

        let has_action_ref = augmented
            .get("action_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        if !has_action_ref {
            return Err(DaemonTransportError::Protocol(
                "missing action_ref for access.request".to_string(),
            ));
        }
        let has_resource_id = augmented
            .get("resource_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        let has_target = augmented.get("target").is_some();
        if !has_resource_id && !has_target {
            return Err(DaemonTransportError::Protocol(
                "access.request requires resource_id or typed target".to_string(),
            ));
        }

        augmented
            .entry("tool_name".to_string())
            .or_insert_with(|| serde_json::Value::String("mcp/access.request".to_string()));
        augmented
            .entry("agent_framework".to_string())
            .or_insert_with(|| serde_json::Value::String("mcp".to_string()));
        if let Some(host) = augmented
            .get("resource_id")
            .and_then(|v| v.as_str())
            .and_then(Self::extract_host)
        {
            augmented
                .entry("target_host".to_string())
                .or_insert_with(|| serde_json::Value::String(host.clone()));
            augmented
                .entry("target_url".to_string())
                .or_insert_with(|| serde_json::Value::String(host));
        }

        Ok(serde_json::Value::Object(augmented))
    }

    /// Execute an MCP tool call by routing through the daemon.
    ///
    /// Per ADR 173 §Component 5 "Soft fail-closed at 90% TTL": if the
    /// mTLS bridge transport's refresh client has flipped the
    /// `refresh_failing` flag (no successful refresh has landed at the
    /// 90% band), NEW tool calls refuse with
    /// [`DaemonTransportError::RefreshFailing`]. In-flight calls already
    /// past this gate continue uninterrupted. The refresh-RPC path
    /// itself uses [`Self::call_raw`] and is NOT gated — refresh
    /// attempts must continue running even after the 90% band.
    pub fn call_tool(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, DaemonTransportError> {
        if let Transport::Mtls { config, .. } = &self.inner {
            if config.is_refresh_failing() {
                return Err(DaemonTransportError::RefreshFailing);
            }
        }
        let translated: Option<serde_json::Value> = match tool_name {
            "access.request" => Some(Self::translate_access_request(arguments)?),
            _ => None,
        };
        let (method, params_ref): (&str, &serde_json::Value) = match tool_name {
            "access.request" => (
                "request_access",
                translated.as_ref().expect("translated set above"),
            ),
            _ => {
                let m = Self::map_tool_to_method(tool_name)
                    .ok_or_else(|| DaemonTransportError::UnknownTool(tool_name.to_string()))?;
                (m, arguments)
            }
        };

        self.call_raw(method, params_ref)
    }

    /// Call a daemon JSON-RPC method by name, bypassing the MCP tool→method
    /// map. Used by bridge maintenance tasks such as
    /// `bridge.cert_expiring_soon`.
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
                // every connect (ADR 154 component 1). The handshake
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
    /// transport's dedicated runtime so the stdio server can remain on a
    /// current-thread runtime without nested-runtime panics.
    fn mtls_round_trip(
        config: &MtlsBridgeConfig,
        runtime: &Arc<tokio::runtime::Runtime>,
        request_line: &str,
    ) -> Result<String, DaemonTransportError> {
        let request = request_line.to_owned();
        let endpoint = config.endpoint.clone();
        let server_name_str = config.server_name.clone();
        // per_rpc_connect_then_close_pattern — snapshot the current
        // ClientConfig on every RPC so a concurrent
        // `swap_client_config` is picked up on the *next* call without
        // disturbing this one. The snapshot is a cheap Arc clone; the
        // read lock is released before the `.await` so we never carry a
        // !Send guard across an await point.
        let tls_config = config.current_client_config();
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

/// Canonical in-container cert paths (ADR 215 §4 — one in-container bridge env
/// contract). The orchestrator mounts the bundle at `/run/ember` and sets the
/// explicit `EMBER_CLIENT_CERT` / `EMBER_CLIENT_KEY` / `EMBER_CA_CERT` paths;
/// `EMBER_BRIDGE_CERT_DIR` overrides the directory for tests / alternate shapes.
/// These mirror `core_construct_runtime::rpc`'s defaults so both in-container
/// consumers of the one contract resolve identically.
pub const DEFAULT_CLIENT_CERT_PATH: &str = "/run/ember/client.crt";
pub const DEFAULT_CLIENT_KEY_PATH: &str = "/run/ember/client.key";
pub const DEFAULT_CA_CERT_PATH: &str = "/run/ember/ca.crt";

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

/// Resolve the client-cert / key / CA paths from the unified in-container bridge
/// env contract (ADR 215 §4), identical to the construct-shim resolution
/// (`core_construct_runtime::rpc::decide_transport`) so both in-container
/// consumers interpret one contract the same way:
///   explicit `EMBER_CLIENT_CERT` → `<EMBER_BRIDGE_CERT_DIR>/client.crt` → default
/// (and likewise key / ca). Pure function — no I/O.
pub fn resolve_bridge_cert_paths() -> (PathBuf, PathBuf, PathBuf) {
    let cert_dir = std::env::var_os("EMBER_BRIDGE_CERT_DIR").map(PathBuf::from);
    let cert = std::env::var_os("EMBER_CLIENT_CERT")
        .map(PathBuf::from)
        .or_else(|| cert_dir.as_ref().map(|d| d.join("client.crt")))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CLIENT_CERT_PATH));
    let key = std::env::var_os("EMBER_CLIENT_KEY")
        .map(PathBuf::from)
        .or_else(|| cert_dir.as_ref().map(|d| d.join("client.key")))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CLIENT_KEY_PATH));
    let ca = std::env::var_os("EMBER_CA_CERT")
        .map(PathBuf::from)
        .or_else(|| cert_dir.as_ref().map(|d| d.join("ca.crt")))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CA_CERT_PATH));
    (cert, key, ca)
}

/// Derive the `host:port` authority for the raw mTLS dial from the unified
/// `EMBER_BRIDGE_URL` (ADR 215 §4), e.g.
/// `https://host.docker.internal:8765` → `host.docker.internal:8765`.
/// Tolerates a bare `host:port` (no scheme) and strips any trailing path.
/// `core_construct_runtime` consumes the same `EMBER_BRIDGE_URL` directly as a
/// reqwest URL; the raw rustls dial needs only the authority, parsed here.
pub fn endpoint_from_bridge_url(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .to_string()
}

/// Read + parse the three PEM files. Fails closed on any missing or
/// malformed file — the caller (`main.rs`) exits non-zero on Err so the
/// container doesn't silently fall through to an anonymous-client lane.
pub fn load_bridge_cert_files(dir: &Path) -> Result<LoadedBridgeCert, BridgeCertError> {
    load_bridge_cert_from_paths(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
    )
}

/// Read + parse the three PEM files at explicit paths (the unified contract's
/// resolved [`resolve_bridge_cert_paths`] output). Fails closed on any missing
/// or malformed file — the caller exits non-zero so the container never falls
/// through to an anonymous-client lane.
pub fn load_bridge_cert_from_paths(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<LoadedBridgeCert, BridgeCertError> {
    let cert_path = cert_path.to_path_buf();
    let key_path = key_path.to_path_buf();
    let ca_path = ca_path.to_path_buf();

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
///   System roots are NEVER consulted. Closed trust domain per ADR 154.
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
    /// Soft fail-closed: bridge cert refresh has been failing past the
    /// 90% band; new tool calls are refused while in-flight RPCs are
    /// preserved. ADR 173 §Component 5 "Soft fail-closed at 90% TTL".
    /// Anchor: `emberlink_mcp_cert_refresh_client_landed`.
    RefreshFailing,
}

impl std::fmt::Display for DaemonTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
            Self::DaemonError(s) => write!(f, "daemon error: {s}"),
            Self::UnknownTool(s) => write!(f, "unknown tool: {s}"),
            Self::RefreshFailing => write!(
                f,
                "bridge cert refresh failing past 90% TTL band; new RPCs refused (in-flight preserved)"
            ),
        }
    }
}

impl std::error::Error for DaemonTransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_tool_to_method_canonical_control_surface() {
        assert_eq!(
            DaemonTransport::map_tool_to_method("session.describe"),
            Some("describe_runtime_attach_target")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("catalog.search_actions"),
            Some("catalog.search_actions")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("access.request"),
            Some("request_access")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("grant.list"),
            Some("list_grants")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("status.get"),
            Some("status")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("evidence.query"),
            Some("receipt_query")
        );
        assert_eq!(
            DaemonTransport::map_tool_to_method("evidence.get"),
            Some("get_receipt")
        );
    }

    #[test]
    fn removed_tool_names_do_not_map_to_daemon_methods() {
        for name in [
            "request_grant",
            "use_credential",
            "list_grants",
            "grant_status",
            "revoke_grant",
            "delegate_grant",
            "grant_summary",
            "whoami",
            "create_persona",
            "request_access",
            "list_approvals",
            "submit_approval",
            "audit_query",
            "detect_anomalies",
            "list_receipts",
            "get_receipt",
            "daemon_persona",
            "grant_budget_status",
            "vault_list",
            "ping",
        ] {
            assert_eq!(
                DaemonTransport::map_tool_to_method(name),
                None,
                "{name} must not be part of the MCP tool map"
            );
        }
    }

    #[test]
    fn translate_access_request_preserves_manifest_shape() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "resource_id": "api.github.com/repos/octo/repo",
            "action_ref": "registry.ember.systems/ember-systems/ember-gh/pr_list@v1"
        });
        let translated = DaemonTransport::translate_access_request(&args).unwrap();
        assert!(translated.get("action").is_none());
        assert_eq!(translated["tool_name"], "mcp/access.request");
        assert_eq!(translated["agent_framework"], "mcp");
        assert_eq!(translated["target_host"], "api.github.com");
    }

    #[test]
    fn translate_access_request_rejects_removed_action_and_scope() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "action": "credential.access.github-token",
            "action_ref": "registry.ember.systems/ember-systems/ember-gh/pr_list@v1",
            "resource_id": "octo/repo"
        });
        let err = DaemonTransport::translate_access_request(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => assert!(msg.contains("action")),
            other => panic!("expected Protocol error, got {other:?}"),
        }

        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "scope": "github.repo:octo/repo",
            "action_ref": "registry.ember.systems/ember-systems/github:gh.pr.list@1"
        });
        let err = DaemonTransport::translate_access_request(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => assert!(msg.contains("scope")),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn translate_access_request_missing_action_ref_or_target_fails_closed() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "resource_id": "octo/repo"
        });
        let err = DaemonTransport::translate_access_request(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => {
                assert!(msg.contains("action_ref"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }

        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "credential_name": "github-token",
            "action_ref": "registry.ember.systems/ember-systems/github:gh.pr.list@1"
        });
        let err = DaemonTransport::translate_access_request(&args).unwrap_err();
        match err {
            DaemonTransportError::Protocol(msg) => {
                assert!(msg.contains("resource_id") && msg.contains("target"));
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
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
    fn mcp_access_request_populates_tool_fields() {
        // access.request with a URL-like resource_id should populate
        // tool_name and target_host in the translated params so the daemon's
        // approval banner shows richer context.
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "action_ref": "registry.ember.systems/ember-systems/github:gh.pr.list@1",
            "credential_name": "github-token",
            "resource_id": "api.github.com/repos/emberdotlink/emberlink",
            "ttl_secs": 3600
        });
        let translated = DaemonTransport::translate_access_request(&args).unwrap();
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
    fn mcp_access_request_typed_target_does_not_invent_host() {
        let args = serde_json::json!({
            "persona_id": "persona-abc",
            "action_ref": "registry.ember.systems/ember-systems/github:gh.pr.list@1",
            "credential_name": "github-token",
            "target": {"kind": "github_repo", "repo": "emberdotlink/emberlink"}
        });
        let translated = DaemonTransport::translate_access_request(&args).unwrap();
        assert_eq!(translated["tool_name"], "mcp/access.request");
        assert_eq!(translated["agent_framework"], "mcp");
        assert!(
            translated.get("target_host").is_none() || translated["target_host"].is_null(),
            "typed targets should not synthesize target_host unless caller supplies it"
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
