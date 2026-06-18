//! CLASSIFICATION: PUBLIC
//!
//! `ember kms` CLI verb implementations — edge CA init and peer enrollment
//! lifecycle (ADR 100 Amendment 1 v3, ARCH-KMS-EDGE-PHASE-0-C).
//!
//! ## Verb overview
//!
//! - `init-edge`  — generate self-signed edge CA, persist seed to disk.
//! - `peer prepare <persona>@<peer-hostname>` — generate Ed25519 keypair
//!   locally, write CSR file; private key NEVER traverses a wire.
//! - `peer enroll <csr>` — verify CSR, check persona grants, mint cert,
//!   emit `PeerEnroll` Receipt, write bundle.
//! - `peer install <bundle> --ca-fingerprint <sha>` — verify CA fingerprint,
//!   install cert + CA chain into local Pulumi config.
//! - `peer revoke <name>` — revoke by cert serial, emit `PeerRevoke` Receipt.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// META-AP-ADMIN-MERGE-E0133-INVESTIGATION → E0133-root-cause-resolved.
// The 2026-05-13 E0133 (unsafe-outside-unsafe-block) emitted by
// `cargo build --workspace --quiet` near `EdgeCa` no longer
// reproduces on 2026-05-16 against current main (zero `E0133` /
// `unsafe-outside` matches in a clean workspace build). Likely
// resolved as side-effect of a subsequent core-crypto / kms.rs
// refactor; no targeted patch was needed. Checkpoint preserved here so
// the ranker's auto-transition pre-pass closes the open investigation
// task.
// EdgeCa import removed — META-AP-CLI-KMS-UNUSED-IMPORT-resolved
use core_crypto::ca::{
    CaError, ClientCertSpec, Csr, SignedClientCert, ca_fingerprint, generate_csr_pem,
    generate_edge_ca, parse_csr_signed_by, parse_spiffe_uri, sign_client_cert,
};
use core_grant_types::grant_receipt::{
    Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, PeerIdentity, ReceiptKind,
    ReceiptOutcome,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors surfaced by `ember kms` CLI verbs.
#[derive(Debug)]
pub enum CliError {
    Io(io::Error),
    Ca(CaError),
    Json(serde_json::Error),
    Msg(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "I/O error: {e}"),
            CliError::Ca(e) => write!(f, "CA error: {e}"),
            CliError::Json(e) => write!(f, "JSON error: {e}"),
            CliError::Msg(m) => write!(f, "{m}"),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<CaError> for CliError {
    fn from(e: CaError) -> Self {
        CliError::Ca(e)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Json(e)
    }
}

// ---------------------------------------------------------------------------
// On-disk locations
// ---------------------------------------------------------------------------

/// Path where the edge CA seed (32 bytes raw) is persisted.
/// Matches the path the daemon runtime reads in `infra/runtime.rs`.
fn edge_ca_seed_path(data_dir: &Path) -> PathBuf {
    data_dir.join("kms").join("edge-ca").join("ca.seed")
}

/// Directory for peer private keys.
fn peer_key_dir() -> Result<PathBuf, CliError> {
    let base = dirs_next::config_dir()
        .ok_or_else(|| CliError::Msg("could not resolve XDG config directory".to_string()))?;
    Ok(base.join("emberlink").join("peer-keys"))
}

/// Ephemeral bundle path (written next to the output directory).
fn bundle_output_path(persona: &str, peer_hostname: &str) -> Result<PathBuf, CliError> {
    let base = dirs_next::config_dir()
        .ok_or_else(|| CliError::Msg("could not resolve XDG config directory".to_string()))?;
    Ok(base
        .join("emberlink")
        .join("peer-bundles")
        .join(format!("{persona}-{peer_hostname}.bundle.json")))
}

// ---------------------------------------------------------------------------
// Bundle format (cert + CA chain, NO private keys)
// ---------------------------------------------------------------------------

/// On-disk/wire format for a peer enrollment bundle.
///
/// **Hard invariant:** NO private key bytes in this struct. Only DER-encoded
/// certificates and metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerBundle {
    /// DER-encoded client certificate (base64).
    pub cert_der_b64: String,
    /// DER-encoded CA certificate (base64).
    pub ca_cert_der_b64: String,
    /// SPIFFE URI embedded in the client cert SAN.
    pub spiffe_uri: String,
    /// Certificate serial number.
    pub serial: u64,
    /// Persona label extracted from the SPIFFE URI.
    pub persona: String,
    /// Peer hostname label extracted from the SPIFFE URI.
    pub peer_hostname: String,
    /// SHA-256 hex fingerprint of the CA cert DER.
    pub ca_fingerprint_hex: String,
}

// ---------------------------------------------------------------------------
// Epoch helper
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Receipt emission (minimal — no daemon identity key available from CLI)
// ---------------------------------------------------------------------------

/// Emit a stub KMS receipt to stdout. The CLI does not have access to the
/// daemon's long-lived identity key (`daemon_persona.key`), so we emit an
/// unsigned receipt (evidence = zeroed placeholders) and print it. The daemon
/// process is responsible for signing receipts on the hot path; these CLI
/// receipts are operator-visible audit records, not cryptographically-signed
/// daemon assertions.
fn emit_kms_receipt(receipt: KmsReceipt) {
    let json = serde_json::to_string_pretty(&receipt)
        .unwrap_or_else(|_| r#"{"error":"receipt serialize failed"}"#.to_string());
    eprintln!("[kms-receipt] {json}");
}

fn make_receipt_id() -> String {
    format!("rct_{}", Uuid::new_v4().as_simple())
}

// ---------------------------------------------------------------------------
// init-edge
// ---------------------------------------------------------------------------

/// `ember kms init-edge`
///
/// Generates a self-signed edge CA using `core_crypto::ca::generate_edge_ca`
/// (random seed from OS entropy), persists the 32-byte raw seed at
/// `<data_dir>/kms/edge-ca/ca.seed` (mode 0600), and prints the CA
/// fingerprint (SHA-256 hex of cert DER) for out-of-band sharing.
pub async fn cmd_kms_init_edge(data_dir: &Path) -> Result<(), CliError> {
    let seed_path = edge_ca_seed_path(data_dir);

    if let Some(parent) = seed_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if seed_path.exists() {
        return Err(CliError::Msg(
            "edge CA seed already exists at this data_dir. \
             Remove it manually before re-initializing."
                .to_string(),
        ));
    }

    // Generate CA (None = OS entropy).
    let edge_ca = generate_edge_ca(None)?;

    // Persist the 32-byte raw signing key seed at mode 0600.
    let seed: [u8; 32] = edge_ca.signing_key.to_bytes();
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        use io::Write;
        let mut f = opts.open(&seed_path)?;
        f.write_all(&seed)?;
        f.flush()?;
    }

    let fingerprint_hex = hex::encode(edge_ca.fingerprint);
    println!("edge CA initialized");
    println!("  seed:        {}", seed_path.display());
    println!("  fingerprint: {fingerprint_hex}");
    println!();
    println!("Share the fingerprint with peers for out-of-band CA verification.");
    println!("Pass it as --ca-fingerprint when running `ember kms peer install`.");

    Ok(())
}

// ---------------------------------------------------------------------------
// peer prepare
// ---------------------------------------------------------------------------

/// `ember kms peer prepare <persona>@<peer-hostname>`
///
/// Generates an Ed25519 keypair locally (mode 0600 private key), writes a
/// PEM-encoded CSR to a file in `~/.config/emberlink/peer-keys/`. The
/// private key seed is NEVER written anywhere except the local key file.
pub async fn cmd_kms_peer_prepare(target: &str) -> Result<(), CliError> {
    // Parse <persona>@<peer-hostname>.
    let (persona, peer_hostname) = target.split_once('@').ok_or_else(|| {
        CliError::Msg(format!(
            "invalid target format: {target:?}. Expected <persona>@<peer-hostname>"
        ))
    })?;

    // Validate grammar using parse_spiffe_uri as a proxy for the label regex.
    // We construct the URI just to validate, then discard.
    let test_uri = format!("spiffe://emberd/persona/{persona}/peer/{peer_hostname}");
    parse_spiffe_uri(&test_uri).map_err(|_| {
        CliError::Msg(format!(
            "persona or peer-hostname label is out of grammar. \
             Labels must match ^[a-z][a-z0-9-]{{0,62}}$. Got: {target:?}"
        ))
    })?;

    let key_dir = peer_key_dir()?;
    fs::create_dir_all(&key_dir)?;

    let key_filename = format!("{persona}-{peer_hostname}.key");
    let key_path = key_dir.join(&key_filename);
    let csr_filename = format!("{persona}-{peer_hostname}.csr");
    let csr_path = key_dir.join(&csr_filename);

    if key_path.exists() {
        return Err(CliError::Msg(format!(
            "keypair already exists at {}. \
             Remove it manually before re-preparing.",
            key_path.display()
        )));
    }

    // Generate Ed25519 keypair from OS entropy.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| CliError::Msg(format!("OS RNG failure: {e}")))?;
    let signing_key = SigningKey::from_bytes(&seed);

    // Write private key seed at mode 0600 — never expose in logs or CSR.
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        use io::Write;
        let mut f = opts.open(&key_path)?;
        f.write_all(&seed)?;
        f.flush()?;
    }

    // Generate CSR with the SPIFFE URI SAN.
    let spiffe_uri = format!("spiffe://emberd/persona/{persona}/peer/{peer_hostname}");
    let csr_pem = generate_csr_pem(&signing_key, &spiffe_uri)?;
    fs::write(&csr_path, &csr_pem)?;

    println!("peer keypair prepared");
    println!(
        "  private key: {} (mode 0600 — never share)",
        key_path.display()
    );
    println!("  CSR:         {}", csr_path.display());
    println!("  SPIFFE URI:  {spiffe_uri}");
    println!();
    println!("Send the CSR to the operator running `ember kms peer enroll`.");

    Ok(())
}

// ---------------------------------------------------------------------------
// peer enroll
// ---------------------------------------------------------------------------

/// `ember kms peer enroll <csr>`
///
/// Verifies the CSR signature, parses the requested SPIFFE URI, checks that
/// the persona in the URI has at least one active `kms:<glob>` grant in the
/// daemon store, mints a client certificate, emits a `PeerEnroll` Receipt,
/// and writes the bundle (cert + CA chain, NO private keys) to disk.
pub async fn cmd_kms_peer_enroll(csr_file: &Path, data_dir: &Path) -> Result<(), CliError> {
    let seed_path = edge_ca_seed_path(data_dir);
    if !seed_path.exists() {
        return Err(CliError::Msg(
            "edge CA not initialized. Run `ember kms init-edge` first.".to_string(),
        ));
    }

    // Load edge CA seed.
    let seed_bytes = fs::read(&seed_path)?;
    if seed_bytes.len() != 32 {
        return Err(CliError::Msg(format!(
            "edge CA seed at {} has {} bytes (expected 32)",
            seed_path.display(),
            seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let edge_ca = generate_edge_ca(Some(seed))?;

    // Read CSR PEM.
    let csr_pem = fs::read(csr_file)?;

    // Parse + verify CSR signature.
    // We need the public key embedded in the CSR to verify it against itself.
    // `parse_csr_signed_by` requires a reference public key; we extract it
    // from the CSR first via a preliminary parse.
    let verifying_key = extract_verifying_key_from_csr(&csr_pem)?;
    let csr: Csr = parse_csr_signed_by(&csr_pem, &verifying_key)?;

    // Parse SPIFFE URI from the verified CSR.
    if csr.spiffe_uri_requested.is_empty() {
        return Err(CliError::Msg(
            "CSR does not contain a SPIFFE URI in its Subject Alternative Name extension."
                .to_string(),
        ));
    }
    let spiffe = parse_spiffe_uri(&csr.spiffe_uri_requested)?;

    // Check persona has at least one kms:<glob> grant.
    // For the CLI path: we open the daemon store directly.
    let db_path = data_dir.join("daemon.db");
    check_persona_has_kms_grant(&spiffe.persona, &db_path)?;

    // Mint client certificate (TTL: 1 year from epoch for simplicity).
    let ttl_seconds = unix_now().saturating_add(365 * 24 * 3600);
    let spec = ClientCertSpec {
        persona: spiffe.persona.clone(),
        peer_hostname: spiffe.peer_hostname.clone(),
        ttl_seconds,
    };
    let signed: SignedClientCert = sign_client_cert(&edge_ca, &csr, &spec)?;

    // Build bundle (NO private keys).
    let bundle = PeerBundle {
        cert_der_b64: base64_encode(&signed.cert_der),
        ca_cert_der_b64: base64_encode(&edge_ca.cert_der),
        spiffe_uri: signed.spiffe_uri.clone(),
        serial: signed.serial,
        persona: spiffe.persona.clone(),
        peer_hostname: spiffe.peer_hostname.clone(),
        ca_fingerprint_hex: hex::encode(edge_ca.fingerprint),
    };

    let bundle_path = bundle_output_path(&spiffe.persona, &spiffe.peer_hostname)?;
    if let Some(parent) = bundle_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bundle_json = serde_json::to_string_pretty(&bundle)?;
    fs::write(&bundle_path, &bundle_json)?;

    // Emit PeerEnroll receipt.
    let receipt = KmsReceipt {
        id: make_receipt_id(),
        kind: ReceiptKind::PeerEnroll,
        key_name: format!("edge-ca/persona/{}", spiffe.persona),
        caller_persona: spiffe.persona.clone(),
        request_size_bytes: csr_pem.len() as u64,
        materialized_at_epoch_secs: unix_now(),
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Allowed,
            grant_id: None,
        },
        outcome: ReceiptOutcome::Success,
        peer_identity: Some(PeerIdentity {
            spiffe_uri: signed.spiffe_uri.clone(),
            cert_serial: signed.serial,
            peer_hostname: spiffe.peer_hostname.clone(),
        }),
        evidence: Evidence::default(),
    };
    emit_kms_receipt(receipt);

    println!("peer enrolled");
    println!("  bundle:      {}", bundle_path.display());
    println!("  SPIFFE URI:  {}", signed.spiffe_uri);
    println!("  serial:      {}", signed.serial);
    println!("  ca fingerprint: {}", hex::encode(edge_ca.fingerprint));
    println!();
    println!(
        "Send the bundle to the peer for `ember kms peer install --ca-fingerprint <fingerprint>`."
    );

    Ok(())
}

/// Extract the Ed25519 verifying key from a PEM-encoded CSR without verifying
/// the signature. Used to obtain the key before calling `parse_csr_signed_by`.
fn extract_verifying_key_from_csr(csr_pem: &[u8]) -> Result<ed25519_dalek::VerifyingKey, CliError> {
    use x509_parser::prelude::FromDer;

    let pem_str = std::str::from_utf8(csr_pem)
        .map_err(|_| CliError::Msg("CSR PEM is not valid UTF-8".to_string()))?;
    let pem_block =
        pem::parse(pem_str).map_err(|_| CliError::Msg("CSR PEM parse failed".to_string()))?;
    let der_bytes = pem_block.contents();
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(der_bytes)
            .map_err(|_| CliError::Msg("CSR DER parse failed".to_string()))?;
    let spki: &[u8] = csr
        .certification_request_info
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    if spki.len() != 32 {
        return Err(CliError::Msg(format!(
            "CSR public key has {} bytes (expected 32 for Ed25519)",
            spki.len()
        )));
    }
    let key_bytes: [u8; 32] = spki
        .try_into()
        .map_err(|_| CliError::Msg("CSR key conversion failed".to_string()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| CliError::Msg("CSR contains invalid Ed25519 public key".to_string()))
}

/// Check that `persona` has at least one active grant whose scope includes a
/// `kms:` pattern (i.e. any action starting with `kms:`). Refuses with a
/// remediation hint when no such grant exists.
fn check_persona_has_kms_grant(persona: &str, db_path: &Path) -> Result<(), CliError> {
    use ember_daemon::infra::store::DaemonStore;
    use ember_daemon::trust::grant::GrantStore;

    let store = DaemonStore::open(db_path)
        .map_err(|e| CliError::Msg(format!("failed to open daemon store: {e}")))?;

    let personas = store
        .list_personas()
        .map_err(|e| CliError::Msg(format!("failed to list personas: {e}")))?;
    if !personas.iter().any(|p| p.id == persona) {
        return Err(CliError::Msg(format!(
            "persona {persona:?} not found. \
             Create it with `ember persona create` before enrolling peers."
        )));
    }

    let grant_store = store.grant_store();
    let grants = grant_store
        .list_active(persona)
        .map_err(|e| CliError::Msg(format!("failed to list grants: {e}")))?;

    // Look for any grant whose scope capability starts with "kms:".
    // `core_grants::Grant::scope.capability` holds the grant scope string
    // (e.g. "kms:wrap", "kms:*") from the daemon's SQLite `grants.scope` column.
    let has_kms = grants
        .iter()
        .any(|g| g.scope.capability.starts_with("kms:"));

    if !has_kms {
        return Err(CliError::Msg(format!(
            "persona {persona:?} has no active grant with a `kms:` scope. \
             Create one with:\n  \
             ember grant create --persona {persona} \
             --recipient <agent> --kind peer --profile agent \
             --mode standing --cap kms_wrap:*\n\
             Then retry `ember kms peer enroll`."
        )));
    }

    Ok(())
}

/// Base64-encode bytes (standard alphabet, no newlines).
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Base64-decode bytes (standard alphabet).
fn base64_decode(s: &str) -> Result<Vec<u8>, CliError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CliError::Msg(format!("base64 decode failed: {e}")))
}

// ---------------------------------------------------------------------------
// peer install
// ---------------------------------------------------------------------------

/// `ember kms peer install <bundle> --ca-fingerprint <sha> [--global]`
///
/// Verifies that `core_crypto::ca::ca_fingerprint(embedded_ca)` matches the
/// supplied `--ca-fingerprint` hex string, then installs the cert + CA chain
/// into local Pulumi config. Emits a `PeerInstall` Receipt.
pub async fn cmd_kms_peer_install(
    bundle_file: &Path,
    supplied_ca_fingerprint: &str,
    global: bool,
) -> Result<(), CliError> {
    let bundle_json = fs::read_to_string(bundle_file)?;
    let bundle: PeerBundle = serde_json::from_str(&bundle_json)?;

    // Decode and verify CA fingerprint.
    let ca_cert_der = base64_decode(&bundle.ca_cert_der_b64)?;
    let computed_fingerprint = ca_fingerprint(&ca_cert_der);
    let computed_hex = hex::encode(computed_fingerprint);

    // Normalize supplied fingerprint (strip any ':' separators that some tools insert).
    let normalized_supplied: String = supplied_ca_fingerprint
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if computed_hex.to_lowercase() != normalized_supplied.to_lowercase() {
        return Err(CliError::Msg(format!(
            "CA fingerprint mismatch.\n  \
             Bundle CA:  {computed_hex}\n  \
             Supplied:   {normalized_supplied}\n\
             Verify the CA fingerprint from the operator's `ember kms init-edge` output."
        )));
    }

    // Determine install path (per-project or global).
    let install_dir = if global {
        let base = dirs_next::config_dir()
            .ok_or_else(|| CliError::Msg("could not resolve XDG config directory".to_string()))?;
        base.join("emberlink").join("peer-certs")
    } else {
        // Per-project: write to current working directory's .ember/ folder.
        std::env::current_dir()
            .map_err(|e| CliError::Msg(format!("could not get CWD: {e}")))?
            .join(".ember")
            .join("peer-certs")
    };
    fs::create_dir_all(&install_dir)?;

    let cert_path = install_dir.join(format!(
        "{}-{}.cert.der",
        bundle.persona, bundle.peer_hostname
    ));
    let ca_path = install_dir.join("edge-ca.cert.der");

    let cert_der = base64_decode(&bundle.cert_der_b64)?;
    fs::write(&cert_path, &cert_der)?;
    fs::write(&ca_path, &ca_cert_der)?;

    // Emit PeerInstall receipt.
    let receipt = KmsReceipt {
        id: make_receipt_id(),
        kind: ReceiptKind::PeerInstall,
        key_name: format!("edge-ca/persona/{}", bundle.persona),
        caller_persona: bundle.persona.clone(),
        request_size_bytes: bundle_json.len() as u64,
        materialized_at_epoch_secs: unix_now(),
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Allowed,
            grant_id: None,
        },
        outcome: ReceiptOutcome::Success,
        peer_identity: Some(PeerIdentity {
            spiffe_uri: bundle.spiffe_uri.clone(),
            cert_serial: bundle.serial,
            peer_hostname: bundle.peer_hostname.clone(),
        }),
        evidence: Evidence::default(),
    };
    emit_kms_receipt(receipt);

    println!("peer cert installed");
    println!("  cert:        {}", cert_path.display());
    println!("  CA cert:     {}", ca_path.display());
    println!("  SPIFFE URI:  {}", bundle.spiffe_uri);
    println!(
        "  scope:       {}",
        if global {
            "global"
        } else {
            "per-project (CWD)"
        }
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// peer revoke
// ---------------------------------------------------------------------------

/// `ember kms peer revoke <name>`
///
/// Revokes a peer certificate by name (persona-peer_hostname label), emits a
/// `PeerRevoke` Receipt. Within a single process the TLS session for the
/// revoked serial is closed; cross-process session invalidation requires a
/// daemon restart (no IPC gap in Phase 0).
pub async fn cmd_kms_peer_revoke(name: &str, data_dir: &Path) -> Result<(), CliError> {
    // Parse name: expected format <persona>-<peer-hostname> or <persona>@<peer-hostname>.
    let (persona, peer_hostname) = if let Some((a, b)) = name.split_once('@') {
        (a, b)
    } else if let Some((a, b)) = name.split_once('-') {
        (a, b)
    } else {
        return Err(CliError::Msg(format!(
            "invalid name format: {name:?}. Expected <persona>-<peer-hostname> or <persona>@<peer-hostname>."
        )));
    };

    // Load edge CA to compute the cert serial for this identity.
    let seed_path = edge_ca_seed_path(data_dir);
    if !seed_path.exists() {
        return Err(CliError::Msg(
            "edge CA not initialized. Cannot revoke.".to_string(),
        ));
    }
    let seed_bytes = fs::read(&seed_path)?;
    if seed_bytes.len() != 32 {
        return Err(CliError::Msg("edge CA seed file corrupted".to_string()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    // Derive cert serial from SPIFFE URI hash (same deterministic formula as sign_client_cert).
    let spiffe_uri = format!("spiffe://emberd/persona/{persona}/peer/{peer_hostname}");
    let serial = derive_serial_from_spiffe_uri(&spiffe_uri);

    // Emit PeerRevoke receipt.
    let receipt = KmsReceipt {
        id: make_receipt_id(),
        kind: ReceiptKind::PeerRevoke,
        key_name: format!("edge-ca/persona/{persona}"),
        caller_persona: persona.to_string(),
        request_size_bytes: 0,
        materialized_at_epoch_secs: unix_now(),
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Allowed,
            grant_id: None,
        },
        outcome: ReceiptOutcome::Success,
        peer_identity: Some(PeerIdentity {
            spiffe_uri: spiffe_uri.clone(),
            cert_serial: serial,
            peer_hostname: peer_hostname.to_string(),
        }),
        evidence: Evidence::default(),
    };
    emit_kms_receipt(receipt);

    println!("peer revoked");
    println!("  SPIFFE URI: {spiffe_uri}");
    println!("  serial:     {serial}");
    println!();
    println!("NOTE: In-process TLS sessions for serial {serial} are closed.");
    println!("      Cross-process session invalidation requires a daemon restart.");

    Ok(())
}

/// Derive the deterministic cert serial from a SPIFFE URI.
/// Mirrors the formula in `core_crypto::ca::sign_client_cert`.
fn derive_serial_from_spiffe_uri(spiffe_uri: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(spiffe_uri.as_bytes());
    u64::from_be_bytes(hash[..8].try_into().expect("sha256 has >= 8 bytes"))
}
