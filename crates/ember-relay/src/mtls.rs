//! CLASSIFICATION: PUBLIC
//!
//! mTLS server + client config loaders for ember-relay.
//!
//! Both binaries read their cert material from PEM files on disk. The host
//! relay builds a [`rustls::ServerConfig`] that REQUIRES a client cert signed
//! by the bundled CA; the VM relay builds a [`rustls::ClientConfig`] that
//! presents its own client cert and trusts only that same CA.
//!
//! The trust root is the bundled CA — system roots are deliberately
//! excluded. This is a closed trust domain.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::RelayError;

/// Install ring as the default rustls crypto provider. Idempotent.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a server config that requires a client cert signed by `ca_pem_path`.
pub fn server_config_from_files(
    cert_pem_path: &Path,
    key_pem_path: &Path,
    ca_pem_path: &Path,
) -> Result<ServerConfig, RelayError> {
    install_default_crypto_provider();

    let server_certs = load_certs(cert_pem_path)?;
    let server_key = load_private_key(key_pem_path)?;
    let root_store = build_root_store(ca_pem_path)?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| RelayError::Tls(format!("build client verifier: {e}")))?;

    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| RelayError::Tls(format!("server cert config: {e}")))
}

/// Build a client config that presents `cert_pem_path` / `key_pem_path` and
/// trusts only `ca_pem_path`.
pub fn client_config_from_files(
    cert_pem_path: &Path,
    key_pem_path: &Path,
    ca_pem_path: &Path,
) -> Result<ClientConfig, RelayError> {
    install_default_crypto_provider();

    let client_certs = load_certs(cert_pem_path)?;
    let client_key = load_private_key(key_pem_path)?;
    let root_store = build_root_store(ca_pem_path)?;

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| RelayError::Tls(format!("client cert config: {e}")))
}

fn build_root_store(ca_pem_path: &Path) -> Result<RootCertStore, RelayError> {
    let ca_certs = load_certs(ca_pem_path)?;
    let mut store = RootCertStore::empty();
    for ca in ca_certs {
        store
            .add(ca)
            .map_err(|e| RelayError::Config(format!("add ca cert: {e}")))?;
    }
    Ok(store)
}

/// Read all PEM `CERTIFICATE` blocks from `path`.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, RelayError> {
    let bytes = std::fs::read(path)
        .map_err(|e| RelayError::Config(format!("read cert {}: {e}", path.display())))?;
    let mut slice: &[u8] = &bytes;
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut slice) {
        let der =
            item.map_err(|e| RelayError::Config(format!("parse cert {}: {e}", path.display())))?;
        out.push(der);
    }
    if out.is_empty() {
        return Err(RelayError::Config(format!(
            "no certificates parsed from {}",
            path.display()
        )));
    }
    Ok(out)
}

/// Read the first PEM private key from `path`.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, RelayError> {
    let bytes = std::fs::read(path)
        .map_err(|e| RelayError::Config(format!("read key {}: {e}", path.display())))?;
    let mut slice: &[u8] = &bytes;
    if let Some(key) = rustls_pemfile::private_key(&mut slice)
        .map_err(|e| RelayError::Config(format!("parse key {}: {e}", path.display())))?
    {
        return Ok(key);
    }
    Err(RelayError::Config(format!(
        "no private key found in {}",
        path.display()
    )))
}
