//! CLASSIFICATION: PUBLIC
//!
//! `bridge-cli` — mTLS bridge management CLI.
//!
//! ## Subcommands
//!
//! - `ping` — perform a single mTLS handshake against the bridge endpoint and
//!   exit 0 on success. Designed for Docker Compose `healthcheck:` blocks.
//!
//! ## Usage (ping)
//!
//! ```text
//! bridge-cli ping [OPTIONS]
//!
//! Options:
//!   --bridge-url <URL>    Bridge endpoint (default: https://host.docker.internal:4243)
//!   --cert <PATH>         Client certificate PEM (default: /run/ember/client.crt)
//!   --key <PATH>          Client private key PEM (default: /run/ember/client.key)
//!   --ca <PATH>           CA certificate PEM (default: /run/ember/ca.crt)
//!   --timeout-secs <N>    Connection + handshake timeout in seconds (default: 5)
//! ```
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | mTLS handshake succeeded; application-layer `HEAD /healthz` received 2xx |
//! | 1    | Connection refused (`BRIDGE_CONNECT_REFUSED`) |
//! | 2    | Connection or handshake timed out (`BRIDGE_CONNECT_TIMEOUT`) |
//! | 3    | TLS handshake failed: cert error, CA mismatch, or protocol error (`BRIDGE_TLS_HANDSHAKE_FAIL`) |
//! | 4    | Configuration error (bad path, unreadable PEM, invalid URL) |
//!
//! ## Docker Swarm foot-gun
//!
//! `service_healthy` dependency ordering is NOT honored under Docker Swarm
//! mode. Healthchecks still execute and produce healthy/unhealthy status, but
//! Swarm ignores `depends_on: condition: service_healthy` when scheduling
//! services across the swarm. The bridge container and its dependents may
//! start in any order. Callers in Swarm environments MUST implement their own
//! retry logic (e.g. exponential backoff in the orchestrator sidecar) rather
//! than relying on `service_healthy` ordering guarantees.
//!
//! bridge-cli-ping-subcommand

use std::path::PathBuf;
use std::process;
use std::time::Duration;

use clap::{Parser, Subcommand};

/// Exit codes for classified bridge errors.
const EXIT_SUCCESS: i32 = 0;
const EXIT_CONNECT_REFUSED: i32 = 1;
const EXIT_CONNECT_TIMEOUT: i32 = 2;
const EXIT_TLS_HANDSHAKE_FAIL: i32 = 3;
const EXIT_CONFIG_ERROR: i32 = 4;

#[derive(Debug, Parser)]
#[command(name = "bridge-cli", about = "mTLS bridge management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Perform a single mTLS handshake against the bridge endpoint.
    ///
    /// Exits 0 on a successful handshake + application-layer ack (HEAD /healthz
    /// returning 2xx). Exits non-zero with a classified error code on any TLS,
    /// connection, or cert-trust failure. Designed for Docker Compose
    /// `healthcheck:` blocks.
    ///
    /// NOTE — Docker Swarm foot-gun: `service_healthy` is NOT honored under
    /// Docker Swarm. See module-level documentation for details.
    Ping(PingArgs),
}

#[derive(Debug, clap::Args)]
struct PingArgs {
    /// Bridge endpoint URL. Defaults to `EMBER_BRIDGE_URL` env var or
    /// `https://host.docker.internal:4243`.
    #[arg(long, env = "EMBER_BRIDGE_URL")]
    bridge_url: Option<String>,

    /// Client certificate PEM path. Defaults to `EMBER_CLIENT_CERT` env var
    /// or `/run/ember/client.crt`.
    #[arg(long, env = "EMBER_CLIENT_CERT")]
    cert: Option<PathBuf>,

    /// Client private key PEM path. Defaults to `EMBER_CLIENT_KEY` env var
    /// or `/run/ember/client.key`.
    #[arg(long, env = "EMBER_CLIENT_KEY")]
    key: Option<PathBuf>,

    /// CA certificate PEM path used to verify the bridge server cert. Defaults
    /// to `EMBER_CA_CERT` env var or `/run/ember/ca.crt`.
    #[arg(long, env = "EMBER_CA_CERT")]
    ca: Option<PathBuf>,

    /// Connection + handshake timeout in seconds.
    #[arg(long, default_value = "5")]
    timeout_secs: u64,
}

impl PingArgs {
    fn bridge_url(&self) -> String {
        self.bridge_url
            .clone()
            .unwrap_or_else(|| "https://host.docker.internal:4243".to_string())
    }

    fn cert_path(&self) -> PathBuf {
        self.cert
            .clone()
            .unwrap_or_else(|| PathBuf::from("/run/ember/client.crt"))
    }

    fn key_path(&self) -> PathBuf {
        self.key
            .clone()
            .unwrap_or_else(|| PathBuf::from("/run/ember/client.key"))
    }

    fn ca_path(&self) -> PathBuf {
        self.ca
            .clone()
            .unwrap_or_else(|| PathBuf::from("/run/ember/ca.crt"))
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Commands::Ping(args) => run_ping(args).await,
    };
    process::exit(exit_code);
}

async fn run_ping(args: PingArgs) -> i32 {
    let bridge_url = args.bridge_url();
    let cert_path = args.cert_path();
    let key_path = args.key_path();
    let ca_path = args.ca_path();
    let timeout = Duration::from_secs(args.timeout_secs);

    // Read client cert PEM.
    let cert_pem = match std::fs::read(&cert_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "bridge-cli ping: BRIDGE_CONFIG_ERROR: cannot read cert {}: {e}",
                cert_path.display()
            );
            return EXIT_CONFIG_ERROR;
        }
    };

    // Read client key PEM.
    let key_pem = match std::fs::read(&key_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "bridge-cli ping: BRIDGE_CONFIG_ERROR: cannot read key {}: {e}",
                key_path.display()
            );
            return EXIT_CONFIG_ERROR;
        }
    };

    // Read CA cert PEM.
    let ca_pem = match std::fs::read(&ca_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "bridge-cli ping: BRIDGE_CONFIG_ERROR: cannot read CA cert {}: {e}",
                ca_path.display()
            );
            return EXIT_CONFIG_ERROR;
        }
    };

    // Concatenate cert + key PEM for reqwest Identity (it expects both in one
    // buffer: cert block(s) first, then the private key block).
    let mut identity_pem = cert_pem.clone();
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key_pem);

    // Build the mTLS identity.
    let identity = match reqwest::Identity::from_pem(&identity_pem) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("bridge-cli ping: BRIDGE_CONFIG_ERROR: parse client identity PEM: {e}");
            return EXIT_CONFIG_ERROR;
        }
    };

    // Build the CA cert for server verification. System roots are
    // deliberately excluded — closed trust domain (ADR 154).
    let ca_cert = match reqwest::Certificate::from_pem(&ca_pem) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bridge-cli ping: BRIDGE_CONFIG_ERROR: parse CA cert PEM: {e}");
            return EXIT_CONFIG_ERROR;
        }
    };

    // Build the reqwest client: present client identity, trust only our CA.
    // `tls_certs_only` sets the CA root AND excludes system roots —
    // closed trust domain (ADR 154).
    let client = match reqwest::Client::builder()
        .use_rustls_tls()
        .identity(identity)
        .tls_certs_only(std::iter::once(ca_cert))
        .timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bridge-cli ping: BRIDGE_CONFIG_ERROR: build TLS client: {e}");
            return EXIT_CONFIG_ERROR;
        }
    };

    // Derive the healthz URL.
    let healthz_url = format!("{}/healthz", bridge_url.trim_end_matches('/'));

    // Issue HEAD /healthz — exercises the full mTLS handshake + confirms the
    // application layer is up. HEAD is idempotent and generates no response
    // body.
    let response = match client.head(&healthz_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return classify_reqwest_error(&e, &bridge_url);
        }
    };

    let status = response.status();
    if status.is_success() {
        eprintln!(
            "bridge-cli ping: ok — {} {} (mTLS handshake succeeded)",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        );
        EXIT_SUCCESS
    } else {
        eprintln!(
            "bridge-cli ping: BRIDGE_TLS_HANDSHAKE_FAIL: unexpected status {} from {healthz_url}",
            status.as_u16()
        );
        EXIT_TLS_HANDSHAKE_FAIL
    }
}

/// Map a `reqwest::Error` to a classified bridge exit code.
///
/// Classification order:
/// 1. Timeout → `BRIDGE_CONNECT_TIMEOUT` (exit 2)
/// 2. TLS / certificate error → `BRIDGE_TLS_HANDSHAKE_FAIL` (exit 3)
/// 3. Connection refused / OS-level connect error → `BRIDGE_CONNECT_REFUSED` (exit 1)
/// 4. Anything else → `BRIDGE_TLS_HANDSHAKE_FAIL` (exit 3, conservative)
fn classify_reqwest_error(e: &reqwest::Error, bridge_url: &str) -> i32 {
    if e.is_timeout() {
        eprintln!("bridge-cli ping: BRIDGE_CONNECT_TIMEOUT: {bridge_url}: {e}");
        return EXIT_CONNECT_TIMEOUT;
    }

    // reqwest wraps TLS errors as "connect" errors — check the debug repr
    // to distinguish OS connect-refused from TLS failures.
    let err_str = format!("{e:?}");
    if e.is_connect() {
        // "Connection refused" from the OS comes through as is_connect() + no
        // TLS keyword in the chain. TLS handshake failures also appear as
        // is_connect() but contain "tls", "certificate", "handshake", "ssl",
        // "rustls", or "unknown issuer" in the debug chain.
        let lower = err_str.to_lowercase();
        let is_tls = lower.contains("tls")
            || lower.contains("certificate")
            || lower.contains("handshake")
            || lower.contains("ssl")
            || lower.contains("rustls")
            || lower.contains("unknown issuer")
            || lower.contains("pkix");

        if is_tls {
            eprintln!("bridge-cli ping: BRIDGE_TLS_HANDSHAKE_FAIL: {bridge_url}: {e}");
            EXIT_TLS_HANDSHAKE_FAIL
        } else {
            eprintln!("bridge-cli ping: BRIDGE_CONNECT_REFUSED: {bridge_url}: {e}");
            EXIT_CONNECT_REFUSED
        }
    } else {
        eprintln!("bridge-cli ping: BRIDGE_TLS_HANDSHAKE_FAIL: {bridge_url}: {e}");
        EXIT_TLS_HANDSHAKE_FAIL
    }
}
