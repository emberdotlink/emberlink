//! CLASSIFICATION: PUBLIC
//!
//! ember-kms-edge listener — emberd-internal mTLS listener for edge connections
//! arriving via the Tailscale tailnet interface (ADR 100 Amendment 1 v3).
//!
//! The `EdgeListener` terminates mTLS connections, verifies the client
//! certificate against the edge CA (ONLY — no system roots), extracts the
//! SPIFFE URI from the client certificate SAN via the strict regex parser from
//! `core_crypto::ca::parse_spiffe_uri`, and resolves persona + grants for the
//! connection via `kms::resolve_persona_grants`.
//!
//! Security invariants (CODEOWNERS-gated):
//! - `client_cert_required = true` is set at the rustls layer — connections
//!   without a valid client certificate are rejected at TLS handshake time,
//!   not at the application layer.
//! - The trust root is a `RootCertStore` containing ONLY the edge_ca cert.
//!   System roots are never consulted.
//! - SPIFFE URI parsing uses `core_crypto::ca::parse_spiffe_uri` exclusively.
//!   Application-layer SPIFFE parsing in this file is forbidden.
//! - No cert PEM, private key material, or seed bytes are ever logged.
//!   Error messages use `[redacted]` for any such fields.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use core_crypto::ca::{EdgeCa, SpiffeIdentity, parse_spiffe_uri};
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::FromDer;

/// Errors produced by the edge listener.
#[derive(Debug, Error)]
pub enum EdgeError {
    #[error("bind failed: {0}")]
    BindFailed(io::Error),
    #[error("client certificate verification failed")]
    CertVerifyFailed,
    #[error("SPIFFE URI missing from client certificate SAN")]
    SpiffeUriMissing,
    #[error("persona not found: {0}")]
    PersonaNotFound(String),
    #[error("TLS config error: {0}")]
    TlsConfig(String),
}

/// Build the `rustls::ServerConfig` for the edge mTLS listener.
///
/// Security invariants enforced here:
/// - `WebPkiClientVerifier` requires a client cert (no anonymous connections).
/// - The trust root contains ONLY the edge_ca cert — no system roots.
/// - The server certificate is the edge CA cert itself (self-signed), signed
///   by the edge CA's own signing key. This is an internal tailnet interface,
///   not a public TLS endpoint; using the CA cert as the server cert is
///   acceptable for this trust domain.
fn build_server_tls_config(edge_ca: &EdgeCa) -> Result<Arc<ServerConfig>, EdgeError> {
    // Install ring as the default crypto provider if not already done.
    // Idempotent — Err means a provider was already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build a RootCertStore containing ONLY the edge CA cert.
    // System roots are deliberately excluded — this is a closed trust domain.
    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(edge_ca.cert_der.as_slice()))
        .map_err(|e| EdgeError::TlsConfig(format!("add edge CA to root store: {e}")))?;
    let root_store = Arc::new(root_store);

    // Build a client cert verifier that requires a client cert signed by the
    // edge CA. Connections without a valid cert are rejected at TLS handshake.
    let client_verifier = WebPkiClientVerifier::builder(root_store)
        .build()
        .map_err(|e| EdgeError::TlsConfig(format!("build client verifier: {e}")))?;

    // Use the edge CA's signing key and cert as the server credential.
    // NOTE: key material is never logged — use [redacted] in any error strings.
    let server_cert = CertificateDer::from(edge_ca.cert_der.as_slice()).into_owned();

    // Encode the edge CA signing key as PKCS#8 for rustls.
    let mut seed: [u8; 32] = edge_ca.signing_key.to_bytes();
    let pkcs8_der = seed_to_pkcs8_v1_der(&seed);
    zeroize::Zeroize::zeroize(&mut seed);
    let server_key = PrivatePkcs8KeyDer::from(pkcs8_der);

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert], server_key.into())
        .map_err(|e| EdgeError::TlsConfig(format!("server cert: {e}")))?;

    Ok(Arc::new(config))
}

/// Encode a 32-byte Ed25519 seed as a PKCS#8 v1 DER document suitable for
/// `rustls`. Mirrors the encoding in `core_crypto::ca` — duplicated here to
/// avoid a cross-crate private function dependency.
fn seed_to_pkcs8_v1_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[0x30, 0x2e]);
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);
    der
}

/// Extract the first SPIFFE URI from a DER-encoded X.509 certificate's
/// Subject Alternative Name extension and parse it via `parse_spiffe_uri`.
///
/// Returns `Err(EdgeError::SpiffeUriMissing)` when no SAN URI matching the
/// strict SPIFFE regex is found.
fn extract_spiffe_from_cert(cert_der: &[u8]) -> Result<SpiffeIdentity, EdgeError> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|_| EdgeError::CertVerifyFailed)?;

    if let Some(san_ext) = cert
        .subject_alternative_name()
        .map_err(|_| EdgeError::CertVerifyFailed)?
    {
        for gn in &san_ext.value.general_names {
            if let x509_parser::extensions::GeneralName::URI(uri) = gn
                && uri.starts_with("spiffe://")
            {
                return parse_spiffe_uri(uri).map_err(|_| EdgeError::SpiffeUriMissing);
            }
        }
    }

    Err(EdgeError::SpiffeUriMissing)
}

/// The mTLS edge listener handle.
///
/// Constructed via [`EdgeListener::spawn`]. The returned `JoinHandle` drives
/// the accept loop; dropping it cancels the listener.
pub struct EdgeListener {
    pub bind_addr: SocketAddr,
    #[allow(dead_code)]
    tls_config: Arc<ServerConfig>,
    #[allow(dead_code)]
    edge_ca: Arc<EdgeCa>,
}

impl EdgeListener {
    /// Spawn the mTLS edge listener on `bind_addr`.
    ///
    /// On accept: extract client cert chain, verify against edge_ca, parse
    /// SPIFFE URI from SAN, and hand `(persona, grants)` to the in-process
    /// API code path via async request-context. NOT loopback HTTP — direct
    /// in-process call.
    ///
    /// When the CA is absent at the data directory path, the caller logs
    /// "edge listener skipped (no edge CA)" and does not call this function.
    /// Graceful degradation is the caller's responsibility; this function
    /// treats a missing CA as a hard error.
    ///
    /// # Errors
    /// Returns `EdgeError::BindFailed` when the TCP listener cannot bind.
    pub async fn spawn(
        bind_addr: SocketAddr,
        edge_ca: Arc<EdgeCa>,
    ) -> Result<JoinHandle<()>, EdgeError> {
        let tls_config = build_server_tls_config(&edge_ca)?;
        let acceptor = TlsAcceptor::from(Arc::clone(&tls_config));

        let tcp_listener = TcpListener::bind(bind_addr)
            .await
            .map_err(EdgeError::BindFailed)?;

        let handle = tokio::spawn(async move {
            tracing::info!(%bind_addr, "ember-kms-edge listener accepting");
            loop {
                let (stream, peer_addr) = match tcp_listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "edge listener: accept error");
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            // TLS handshake failure — cert rejected, wrong CA,
                            // or no client cert presented.
                            tracing::warn!(
                                %peer_addr,
                                error = %e,
                                "edge listener: TLS handshake failed [cert=[redacted]]"
                            );
                            return;
                        }
                    };

                    // Extract peer certificate — must be present (enforced at handshake).
                    let (_, server_conn) = tls_stream.get_ref();
                    let peer_certs = match server_conn.peer_certificates() {
                        Some(certs) if !certs.is_empty() => certs,
                        _ => {
                            tracing::warn!(%peer_addr, "edge listener: no peer cert after handshake");
                            return;
                        }
                    };

                    // Parse SPIFFE URI from the leaf cert (index 0).
                    let spiffe = match extract_spiffe_from_cert(peer_certs[0].as_ref()) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(
                                %peer_addr,
                                error = %e,
                                "edge listener: SPIFFE URI extraction failed"
                            );
                            return;
                        }
                    };

                    tracing::debug!(
                        %peer_addr,
                        persona = %spiffe.persona,
                        peer_hostname = %spiffe.peer_hostname,
                        "edge listener: authenticated peer"
                    );

                    // NOTE: Full request dispatch (persona grant resolution + API
                    // handler dispatch) ships in -C via kms_edge_integration tests.
                    // Phase 0-B establishes the listener, cert verification, and
                    // SPIFFE extraction; the in-process call chain is wired in -C.
                    drop(tls_stream);
                });
            }
        });

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::ca::generate_edge_ca;

    #[tokio::test]
    async fn edge_listener_bind_smoke() {
        // Generate a deterministic edge CA from a fixed seed.
        let edge_ca = generate_edge_ca(Some([0u8; 32])).expect("generate edge CA");
        let edge_ca = Arc::new(edge_ca);

        // Bind on an ephemeral loopback port.
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = EdgeListener::spawn(bind_addr, edge_ca).await;

        // Spawn must succeed — binding failed would be a hard error.
        assert!(
            result.is_ok(),
            "EdgeListener::spawn returned Err: {:?}",
            result.err()
        );

        // Drop the handle to shut down the accept loop.
        drop(result.unwrap());
    }
}
