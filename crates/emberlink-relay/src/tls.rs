use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// TLS configuration for the relay.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// No TLS — plain TCP (for local development).
    Plain,
    /// Self-signed certificate generated at startup.
    SelfSigned,
    /// Load certificate and key from files (for Let's Encrypt or other CA certs).
    FromFiles { cert_path: String, key_path: String },
}

/// Build a rustls ServerConfig from the given TLS mode.
pub fn build_server_config(mode: &TlsMode) -> Result<Option<Arc<ServerConfig>>, String> {
    match mode {
        TlsMode::Plain => Ok(None),
        TlsMode::SelfSigned => {
            let (certs, key) = generate_self_signed_cert()?;
            let config = server_config_from_parts(certs, key)?;
            Ok(Some(Arc::new(config)))
        }
        TlsMode::FromFiles {
            cert_path,
            key_path,
        } => {
            let certs = load_certs(cert_path)?;
            let key = load_private_key(key_path)?;
            let config = server_config_from_parts(certs, key)?;
            Ok(Some(Arc::new(config)))
        }
    }
}

/// Install the rustls ring crypto provider as the process default. rustls 0.23
/// no longer auto-selects a provider from enabled features; callers must
/// install one before the first `ServerConfig::builder()`. Idempotent across
/// parallel tests and repeat calls via `Once`.
fn ensure_rustls_provider_installed() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // Ignore `Err` — means a provider was installed by another path earlier.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn server_config_from_parts(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, String> {
    ensure_rustls_provider_installed();
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("TLS server config: {err}"))
}

fn generate_self_signed_cert()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|err| format!("generate self-signed cert: {err}"))?;

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    // rcgen 0.14 renamed `CertifiedKey::key_pair` → `signing_key`.
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der().to_vec(),
    ));

    Ok((vec![cert_der], key_der))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = fs::File::open(path).map_err(|err| format!("open cert file {path}: {err}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse cert file {path}: {err}"))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = fs::File::open(path).map_err(|err| format!("open key file {path}: {err}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|err| format!("parse key file {path}: {err}"))?
        .ok_or_else(|| format!("no private key found in {path}"))
}

/// A stream that can be either plain TCP or TLS-wrapped TCP.
/// Provides uniform Read + Write interface for the relay protocol.
pub enum RelayStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl RelayStream {
    /// Accept a TLS connection on an existing TCP stream, or return it as plain.
    pub fn accept(stream: TcpStream, tls_config: Option<&Arc<ServerConfig>>) -> io::Result<Self> {
        match tls_config {
            None => Ok(Self::Plain(stream)),
            Some(config) => {
                let conn = ServerConnection::new(Arc::clone(config))
                    .map_err(|err| io::Error::other(format!("TLS accept: {err}")))?;
                Ok(Self::Tls(Box::new(StreamOwned::new(conn, stream))))
            }
        }
    }
}

impl Read for RelayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for RelayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}
