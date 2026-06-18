//! Binary manifest types — content-hash-pinned binary discovery per ADR 124 §7.
//!
//! The daemon's `/usr/local/lib/ember/binaries/manifest.toml` binds
//! (tool_name, version) → (absolute_path, blake3 content_hash).
//! `verify_binary_pin` (in `broker_handler.rs`) consumes this on every
//! `broker_exec` call and refuses execution on hash mismatch.
//!
//! ## Binary distribution channel (ADR 124 §7 v0.3.0)
//!
//! v0.3.0 ships **Option A — bundled-with-daemon**: the cohort-A
//! Constructs ([`COHORT_A_CONSTRUCTS`]) ride inside the `emberd` release
//! artifact and land at the canonical bundled-install dir
//! ([`bundled_install_dir`]). Pre-vetted; signed by Ember Systems'
//! IdentityRoot — same trust boundary as the daemon itself. The
//! [`BinaryDistributionChannel`] enum names the choice; the manifest
//! tags each entry with the channel that produced it. Option B
//! (`InstallOnDemand`, `ember binary install <tool>@<version>` from a
//! per-publisher mirror) is deferred to v0.4 — see ADR 124 §7
//! "Binary distribution channel" amendment.
//!
//! Related sub-features:
//! - the `ember binary install/list/update/remove` CLI surface
//! - the manifest signature gate at daemon startup
//! - the v0.3.0 binary distribution channel decision (this file)

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Cohort-A Construct artifact names per ADR 124 §"Cohort-A bundled
/// Constructs". These are the binaries the v0.3.0 release pipeline
/// pre-bundles inside `emberd`'s artifact and the daemon discovers
/// from [`bundled_install_dir`] at startup. Order is stable for
/// release-tooling determinism.
pub const COHORT_A_CONSTRUCTS: &[&str] = &["ember-gh", "ember-git", "ember-kubectl"];

/// Platform-specific RPC sibling admitted by the daemon-side rpc-forward
/// provenance gate. It is not a Construct, but it must live in the same signed
/// runtime manifest so the bridge receiver can prove the peer is the shipped
/// `emberd-rpc` binary before accepting forwarded frames.
#[cfg(target_os = "macos")]
pub const BUNDLED_EMBERD_RPC_TOOL: &str = "emberd-rpc-macos";
#[cfg(target_os = "linux")]
pub const BUNDLED_EMBERD_RPC_TOOL: &str = "emberd-rpc-linux";

#[cfg(target_os = "macos")]
pub fn bundled_emberd_rpc_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/emberd-rpc-macos")
}

#[cfg(target_os = "linux")]
pub fn bundled_emberd_rpc_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/emberd-rpc-linux")
}

/// Where the v0.3.0 release pipeline lays down bundled Construct
/// binaries on disk. The daemon scans this directory at startup +
/// records the entries it finds into the runtime manifest with
/// [`BinaryDistributionChannel::Bundled`].
///
/// Matches ADR 124 §7 manifest-shape `absolute_path` examples
/// (`/usr/local/lib/ember/binaries/<tool>-<version>`).
pub fn bundled_install_dir() -> PathBuf {
    PathBuf::from("/usr/local/lib/ember/binaries")
}

/// Runtime binaries that should be signed into the bundled manifest for a scan
/// rooted at `from_dir`.
///
/// Constructs are read from `from_dir`; the RPC sibling is installed at the
/// platform launcher path (`/usr/local/bin/emberd-rpc-*`) and is included only
/// for the canonical bundled install directory. This keeps tests and custom
/// scans deterministic while making the normal host/release install produce the
/// manifest required by the rpc-forward provenance gate.
pub fn bundled_runtime_manifest_candidates(from_dir: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut candidates = COHORT_A_CONSTRUCTS
        .iter()
        .map(|tool| (*tool, from_dir.join(tool)))
        .collect::<Vec<_>>();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if from_dir == bundled_install_dir() {
        candidates.push((BUNDLED_EMBERD_RPC_TOOL, bundled_emberd_rpc_path()));
    }

    candidates
}

/// Binary distribution channel — names *where* a pinned binary came
/// from, per ADR 124 §7 "binary distribution channel" amendment.
///
/// Recorded per-entry on the manifest so the daemon's audit chain can
/// surface "this `gh` binary shipped inside `emberd` v0.3.0" vs
/// "this `kubectl` was fetched on demand by `ember binary install`".
/// v0.3.0 only emits [`Bundled`](Self::Bundled); [`InstallOnDemand`](Self::InstallOnDemand)
/// is the v0.4 follow-up surface and is parsed-but-rejected at startup
/// for v0.3.0 (defensive — refuses to vend creds against a binary that
/// arrived through a channel the current daemon doesn't yet trust).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum BinaryDistributionChannel {
    /// Cohort-A: shipped inside the `emberd` release artifact. Signed
    /// by Ember Systems' IdentityRoot. Discovered from
    /// [`bundled_install_dir`] at daemon startup.
    #[default]
    Bundled,
    /// v0.4: `ember binary install <tool>@<version>` fetches from a
    /// per-publisher GitHub release or an ember-managed mirror. Each
    /// entry carries its own publisher DID; the daemon validates the
    /// publisher's signature against a per-publisher trust delegation
    /// recorded in the daemon's WoT graph (per ADR 123).
    InstallOnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryManifestEntry {
    pub tool_name: String,
    pub version: String,
    /// blake3 hex-encoded with "blake3:" prefix.
    pub content_hash: String,
    pub absolute_path: PathBuf,
    /// Unix epoch seconds.
    pub installed_at: i64,
    /// Publisher DID (e.g. "did:emberlink" for Ember Systems' bundled identity;
    /// `did:web:<domain>` / `did:key:<base58-pubkey>` for v0.4+ community
    /// publishers per ADR 135).
    pub publisher: String,
    /// Distribution channel that landed this entry on disk. Per ADR
    /// 124 §7 "binary distribution channel" amendment. Defaults to
    /// [`BinaryDistributionChannel::Bundled`] for back-compat with
    /// pre-channel manifests written by older daemons.
    #[serde(default)]
    pub channel: BinaryDistributionChannel,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryManifest {
    #[serde(default)]
    pub entries: Vec<BinaryManifestEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Load a manifest from a TOML file path. Returns an empty manifest if
/// the file doesn't exist (caller decides whether absence is fatal).
pub fn load_manifest(path: &Path) -> Result<BinaryManifest, ManifestError> {
    if !path.exists() {
        return Ok(BinaryManifest::default());
    }
    let bytes = std::fs::read(path)?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| ManifestError::MissingField(format!("not utf8: {e}")))?;
    let manifest: BinaryManifest = toml::from_str(s)?;
    Ok(manifest)
}

/// Lookup error surfaced by [`lookup_construct`].
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// No manifest entry matched the given construct name.
    #[error("construct '{0}' not found in manifest")]
    NotFound(String),
    /// v0.3.0 ships only [`BinaryDistributionChannel::Bundled`]; an
    /// entry with [`BinaryDistributionChannel::InstallOnDemand`] is
    /// rejected defensively until v0.4 lands the dynamic-install
    /// signing pipeline.
    #[error("construct '{name}' uses unsupported channel {channel:?} in v0.3.0")]
    UnsupportedChannel {
        name: String,
        channel: BinaryDistributionChannel,
    },
}

/// Public lookup entry point — bind a Construct artifact name (e.g.
/// `"ember-gh"`) to its manifest entry. Per ADR 124 §7 "binary
/// distribution channel" v0.3.0: only [`BinaryDistributionChannel::Bundled`]
/// entries are vendable. The companion verify step is
/// [`crate::broker::handler::verify_binary_pin`] which re-hashes the
/// on-disk bytes immediately before `execve` (TOCTOU window
/// minimization).
///
/// Callers compose:
///   1. `lookup_construct(&manifest, "ember-gh")` — manifest binding
///   2. `verify_binary_pin(&manifest, &entry.tool_name)` — content-hash check
///   3. daemon spawns the resolved path as supervisor (ADR 124 §1 step 4)
pub fn lookup_construct<'a>(
    manifest: &'a BinaryManifest,
    name: &str,
) -> Result<&'a BinaryManifestEntry, LookupError> {
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.tool_name == name)
        .ok_or_else(|| LookupError::NotFound(name.to_string()))?;

    match entry.channel {
        BinaryDistributionChannel::Bundled => Ok(entry),
        ch @ BinaryDistributionChannel::InstallOnDemand => Err(LookupError::UnsupportedChannel {
            name: name.to_string(),
            channel: ch,
        }),
    }
}

/// Returns true iff `name` is one of [`COHORT_A_CONSTRUCTS`]. Used by
/// the bundled-install discovery path to filter the install-dir scan
/// to known artifacts (defense against a stray binary in
/// [`bundled_install_dir`] being treated as a Construct).
pub fn is_cohort_a_construct(name: &str) -> bool {
    COHORT_A_CONSTRUCTS.contains(&name)
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("missing sidecar at {0}")]
    MissingSidecar(String),
    #[error("sidecar parse: {0}")]
    SidecarParse(String),
    #[error("manifest signature mismatch")]
    SignatureMismatch,
    /// ADR 157 §Component 1 — defense against an empty trust-root set
    /// silently accepting every signature (because "no key rejected"
    /// would otherwise short-circuit to Ok via the for-loop's zero
    /// iterations). The compiled-in release IdentityRoot is always
    /// supplied by `infra/runtime.rs` so this is a programmer error,
    /// not a configuration error — surface it loudly.
    #[error("trust_roots set is empty — caller must supply at least the compiled-in release root")]
    TrustRootsEmpty,
    #[error("invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("invalid signature bytes: {0}")]
    InvalidSignature(String),
    #[error("io: {0}")]
    Io(String),
    #[error("base64: {0}")]
    Base64(String),
}

/// Sidecar JSON envelope for the binary manifest. Mirrors the Construct
/// sidecar shape (#1819): schema_version + ed25519 signature over the
/// canonical TOML bytes of the manifest file. The signature is computed
/// at install time by `ember binary install` (sibling task) using the
/// daemon's IdentityRoot.
#[derive(Debug, serde::Deserialize)]
pub struct ManifestSidecar {
    pub schema_version: u32,
    pub signature: String, // "ed25519:base64..." — strip prefix before decode
    pub signature_alg: String, // must be "ed25519"
}

/// Verify that the manifest at `manifest_path` is signed by the daemon's
/// IdentityRoot. Reads `<manifest_path>.sig` for the sidecar JSON,
/// Ed25519-verifies the signature against `root_pubkey` over the raw
/// bytes of the manifest TOML.
///
/// Single-key convenience wrapper around
/// [`verify_manifest_signature_with_trust_roots`]. Retained for callers
/// (and tests) that pre-date ADR 157's trust-root set parameterization;
/// new call sites SHOULD pass a slice through the trust-root API so
/// dev/prod daemons share one verifier with only the trust-set as input.
pub fn verify_manifest_signature(
    manifest_path: &Path,
    root_pubkey: &VerifyingKey,
) -> Result<(), VerifyError> {
    verify_manifest_signature_with_trust_roots(manifest_path, std::slice::from_ref(root_pubkey))
}

/// ADR 157 §Component 1 — trust-root SET verifier. Reads
/// `<manifest_path>.sig` for the sidecar JSON, then Ed25519-verifies the
/// signature against EACH key in `trust_roots` until one matches.
///
/// The verifier ALWAYS runs (no dev-mode bypass). What differs between
/// dev and prod daemons is the SET of acceptable signers, parameterized
/// via `EMBER_TRUST_ROOTS` (parsed in `infra/config.rs`):
///
/// - Prod daemons: trust_roots = [compiled-in release IdentityRoot].
/// - Dev daemons:  trust_roots = [release IdentityRoot, dev IdentityRoot, …].
///
/// Returns `SignatureMismatch` when no key in the set verifies; returns
/// `TrustRootsEmpty` when the caller passes an empty slice (defense
/// against an empty-trust-set silently accepting everything via "no key
/// rejected").
pub fn verify_manifest_signature_with_trust_roots(
    manifest_path: &Path,
    trust_roots: &[VerifyingKey],
) -> Result<(), VerifyError> {
    if trust_roots.is_empty() {
        return Err(VerifyError::TrustRootsEmpty);
    }

    let sidecar_path = manifest_path.with_extension("toml.sig");
    if !sidecar_path.exists() {
        return Err(VerifyError::MissingSidecar(
            sidecar_path.display().to_string(),
        ));
    }

    let sidecar_bytes = std::fs::read(&sidecar_path).map_err(|e| VerifyError::Io(e.to_string()))?;
    let sidecar: ManifestSidecar = serde_json::from_slice(&sidecar_bytes)
        .map_err(|e| VerifyError::SidecarParse(e.to_string()))?;

    if sidecar.schema_version != 1 {
        return Err(VerifyError::SidecarParse(format!(
            "unsupported schema_version: {}",
            sidecar.schema_version
        )));
    }
    if sidecar.signature_alg != "ed25519" {
        return Err(VerifyError::SidecarParse(format!(
            "unsupported signature_alg: {}",
            sidecar.signature_alg
        )));
    }

    let manifest_bytes =
        std::fs::read(manifest_path).map_err(|e| VerifyError::Io(e.to_string()))?;

    let sig_b64 = sidecar
        .signature
        .strip_prefix("ed25519:")
        .unwrap_or(&sidecar.signature);
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| VerifyError::Base64(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| VerifyError::InvalidSignature(e.to_string()))?;

    // Try each trust root in turn; accept the first that verifies. Walking
    // the set is O(n) in the number of trust roots — n is typically 1 (prod)
    // or 2-3 (dev + org-policy endorsements), so the cost is negligible.
    for pk in trust_roots {
        if pk.verify(&manifest_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(VerifyError::SignatureMismatch)
}

/// Errors raised by [`write_signed_manifest`].
#[derive(Debug, thiserror::Error)]
pub enum WriteSignedError {
    #[error("toml serialize: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("sidecar serialize: {0}")]
    SidecarSerialize(#[from] serde_json::Error),
    #[error("io {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Render `manifest` as TOML, sign the exact TOML bytes with `signer`, and
/// write both the manifest file and its `.sig` JSON sidecar to disk in the
/// shape that [`verify_manifest_signature_with_trust_roots`] expects.
///
/// `manifest_path` is the destination TOML path. The sidecar lands at
/// `manifest_path.with_extension("toml.sig")` to match the verifier's lookup
/// (see [`verify_manifest_signature_with_trust_roots`]).
///
/// The signature is computed over the exact bytes that get written to disk —
/// the manifest is serialized once, signed, and written; the verifier later
/// reads those same bytes and re-checks. Any mismatch (post-sign edit, byte
/// reorder, etc.) trips `VerifyError::SignatureMismatch`.
///
/// The parent directory of `manifest_path` is created if absent so callers
/// don't need to pre-mkdir the destination.
pub fn write_signed_manifest(
    manifest: &BinaryManifest,
    signer: &SigningKey,
    manifest_path: &Path,
) -> Result<(), WriteSignedError> {
    let toml_body = toml::to_string_pretty(manifest)?;
    let toml_bytes = toml_body.as_bytes();

    let sig = signer.sign(toml_bytes);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    let sidecar = serde_json::json!({
        "schema_version": 1,
        "signature": format!("ed25519:{sig_b64}"),
        "signature_alg": "ed25519",
    });
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar)?;

    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| WriteSignedError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    std::fs::write(manifest_path, toml_bytes).map_err(|e| WriteSignedError::Io {
        path: manifest_path.to_path_buf(),
        source: e,
    })?;

    let sidecar_path = manifest_path.with_extension("toml.sig");
    std::fs::write(&sidecar_path, &sidecar_bytes).map_err(|e| WriteSignedError::Io {
        path: sidecar_path,
        source: e,
    })?;

    Ok(())
}

/// ADR 157 §Component 5 — process-global flag mirroring the daemon's
/// dev/prod posture at the trust-set level. Set once at startup by
/// `infra/runtime.rs` after the trust-root set is resolved; consulted by
/// the Receipt-builder to stamp `dev_mode_active: <bool>` on every
/// emitted Receipt.
///
/// The flag is `true` iff any non-release root is in the trust set
/// (i.e. the operator supplied additional signers via
/// `EMBER_TRUST_ROOTS`). `false` for prod daemons running release-only.
///
/// This is the ONLY runtime artifact that distinguishes a dev daemon
/// from a prod daemon — and it's an audit signal, not a behavior
/// switch. Per ADR 157 §Component 5.
static DEV_MODE_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the process-global dev-mode flag (ADR 157 §Component 5).
/// Idempotent; safe to call once at daemon startup. Consumed by Receipt
/// emission code via [`dev_mode_active`].
pub fn set_dev_mode_active(v: bool) {
    DEV_MODE_ACTIVE.store(v, std::sync::atomic::Ordering::SeqCst);
}

/// Read the process-global dev-mode flag (ADR 157 §Component 5). Returns
/// `false` until [`set_dev_mode_active`] is called — the default-prod
/// posture matches the "no `EMBER_TRUST_ROOTS` supplied" runtime path.
pub fn dev_mode_active() -> bool {
    DEV_MODE_ACTIVE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Origin of one entry in the daemon's trust-root set. Operator-supplied
/// roots come from `EMBER_TRUST_ROOTS` per ADR 157; the release root is
/// the compiled-in production signer.
///
/// `serde(rename_all = "snake_case")` so the wire form matches the rest
/// of the daemon's RPC vocabulary (`"release"` / `"operator"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootSource {
    /// The compiled-in production release signer.
    Release,
    /// An operator-supplied additional signer via `EMBER_TRUST_ROOTS`
    /// (also the trigger for `dev_mode_active = true`).
    Operator,
}

/// One row of the daemon's startup trust-root set. Captured at startup
/// so `ember trust list` (and future `show` / `explain`) can answer
/// "what is this daemon prepared to verify against?" without re-reading
/// `EMBER_TRUST_ROOTS` or the binary manifest at query time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootRecord {
    /// Hex-lowercase of the Ed25519 public key bytes (64 chars, 32 bytes).
    /// Stable across daemon restarts for the same key. Matches the
    /// fingerprint shape emitted by `verify.rs::query_trust_roots`.
    pub fingerprint_hex: String,
    /// Whether this root came from the compiled-in release path or an
    /// operator override.
    pub source: TrustRootSource,
}

/// Snapshot of the trust-root records the daemon assembled at startup.
/// `OnceLock` because the snapshot writes once (at startup) and reads
/// many times (every `trust.list` RPC); a `Mutex` over the inner Vec
/// allows the snapshot to be replaced atomically if a future call site
/// (e.g. trust rotation) needs to rebuild it. Reads clone the Vec so
/// callers never hold the lock across an RPC reply.
static TRUST_ROOTS_SNAPSHOT: std::sync::OnceLock<std::sync::Mutex<Vec<TrustRootRecord>>> =
    std::sync::OnceLock::new();

/// Replace the process-global trust-root snapshot. Called once by
/// [`crate::infra::runtime`] at startup after the manifest verifies
/// against the assembled trust set; idempotent (subsequent calls
/// overwrite cleanly).
///
/// The order in `records` is preserved verbatim — typically [Release,
/// Operator-1, Operator-2, ...] so display order matches the order in
/// which the daemon would try each signer.
pub fn set_trust_roots_snapshot(records: Vec<TrustRootRecord>) {
    let cell = TRUST_ROOTS_SNAPSHOT.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut guard = cell.lock().expect("trust-roots snapshot mutex poisoned");
    *guard = records;
}

/// Read the process-global trust-root snapshot. Returns a clone so the
/// caller never holds the lock across an await point.
///
/// Empty until [`set_trust_roots_snapshot`] is called — the default
/// matches the "no startup verification ran" posture (in-memory test
/// stores, single-shot CLI utilities).
pub fn trust_roots_snapshot() -> Vec<TrustRootRecord> {
    match TRUST_ROOTS_SNAPSHOT.get() {
        Some(cell) => cell
            .lock()
            .expect("trust-roots snapshot mutex poisoned")
            .clone(),
        None => Vec::new(),
    }
}

/// Convert a slice of [`VerifyingKey`]s + a count of operator-supplied
/// roots into [`TrustRootRecord`]s. Convention: the first
/// `total - operator_count` entries are `Release` (the compiled-in
/// signer, prepended in [`crate::infra::runtime`]); the remaining
/// `operator_count` entries are `Operator`.
///
/// This is a pure function for test ergonomics — runtime.rs hands in
/// the assembled Vec and the count it tracked; the function does the
/// labeling.
pub fn build_trust_root_records(
    trust_roots: &[VerifyingKey],
    operator_count: usize,
) -> Vec<TrustRootRecord> {
    let total = trust_roots.len();
    let release_count = total.saturating_sub(operator_count);
    trust_roots
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let fingerprint_hex = hex_lower(&key.to_bytes());
            let source = if i < release_count {
                TrustRootSource::Release
            } else {
                TrustRootSource::Operator
            };
            TrustRootRecord {
                fingerprint_hex,
                source,
            }
        })
        .collect()
}

/// Append operator-supplied trust roots, skipping roots already present in the
/// release/default trust set. Returns the number of roots actually appended.
///
/// `EMBER_TRUST_ROOTS` is a channel for additional signers. If a script feeds
/// the compiled release root back through that channel, it must not flip
/// `dev_mode_active` or duplicate the release root in `trust.list`.
pub(crate) fn append_unique_operator_trust_roots(
    trust_roots: &mut Vec<VerifyingKey>,
    operator_roots: impl IntoIterator<Item = VerifyingKey>,
) -> usize {
    let mut appended = 0;
    for root in operator_roots {
        let candidate = root.to_bytes();
        if trust_roots
            .iter()
            .any(|existing| existing.to_bytes() == candidate)
        {
            continue;
        }
        trust_roots.push(root);
        appended += 1;
    }
    appended
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// trust_roots_snapshot_landed

/// ADR 157 §Component 1 — parse a comma-separated list of trust-root
/// fingerprints from operator-supplied configuration (typically
/// `EMBER_TRUST_ROOTS`) into [`VerifyingKey`] values.
///
/// Each entry is a 64-char lower-hex Ed25519 public key. The optional
/// `did:key:` prefix is accepted-and-stripped (so operators can write
/// either `did:key:<hex>` or just `<hex>`); this matches ADR 157's
/// example format `EMBER_TRUST_ROOTS=did:key:abcd…`.
///
/// An empty input string (after whitespace trim) is a legitimate "no
/// additional roots" signal and yields an empty `Vec` — the daemon's
/// startup wiring is responsible for prepending the compiled-in release
/// root before passing the set to the verifier.
///
/// Whitespace around commas is tolerated. Empty entries (e.g. trailing
/// comma) are skipped. Invalid hex / wrong-length entries surface as
/// `VerifyError::InvalidPubkey` so the operator gets actionable feedback
/// rather than silent acceptance.
pub fn parse_trust_roots(raw: &str) -> Result<Vec<VerifyingKey>, VerifyError> {
    let mut out = Vec::new();
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Strip the optional `did:key:` prefix. ADR 157 writes
        // `EMBER_TRUST_ROOTS=did:key:abcd…`; the canonical did:key
        // multicodec wire format is out of scope for the v0.3 primitive
        // (which is what this task lands) — we treat the suffix as raw
        // lower-hex Ed25519 pubkey bytes. The multicodec walk lands
        // alongside the per-publisher WoT delegation graph (ADR 123).
        let hex_part = trimmed.strip_prefix("did:key:").unwrap_or(trimmed);
        if hex_part.len() != 64 {
            return Err(VerifyError::InvalidPubkey(format!(
                "trust-root entry {:?} is not 64 hex chars (got {} chars)",
                trimmed,
                hex_part.len()
            )));
        }
        let raw_bytes = hex::decode(hex_part)
            .map_err(|e| VerifyError::InvalidPubkey(format!("hex decode {:?}: {}", trimmed, e)))?;
        let arr: [u8; 32] = raw_bytes.as_slice().try_into().map_err(|_| {
            VerifyError::InvalidPubkey(format!("trust-root entry {:?} not 32 bytes", trimmed))
        })?;
        let key = VerifyingKey::from_bytes(&arr).map_err(|e| {
            VerifyError::InvalidPubkey(format!("not a valid Ed25519 pubkey {:?}: {}", trimmed, e))
        })?;
        out.push(key);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// peer binary pinning
// ---------------------------------------------------------------------------

/// Error variants surfaced by [`verify_peer_binary`]. Distinct from
/// [`PinError`] / [`LookupError`] because peer-binary verification
/// crosses a different trust boundary: rather than verifying a binary
/// the daemon is about to spawn, it verifies the binary the kernel
/// already attests is on the other end of an open socket. The
/// caller-side broker handlers map this onto error code `-32008`
/// (distinct from `-32004` uid binding mismatch and `-32007`
/// principal-not-alive) so operators can tell the failure modes apart.
#[derive(Debug, thiserror::Error)]
pub enum ManifestVerifyError {
    /// Computed blake3 of `/proc/<pid>/exe` did not match any
    /// `content_hash` in the manifest. The peer's binary is not pinned.
    #[error("binary blake3 hash {hash} not in manifest (peer pid {pid})")]
    HashNotInManifest { pid: i32, hash: String },
    /// Hash matched a manifest entry but the on-disk path of the peer
    /// binary disagrees with the manifest's recorded `absolute_path`.
    /// This is the "hash-collision-on-disk OR daemon mis-config"
    /// surface — the manifest's `absolute_path` is also pinned.
    #[error(
        "binary path {actual:?} not in manifest (peer pid {pid}; manifest expected {expected:?})"
    )]
    PathNotInManifest {
        pid: i32,
        actual: PathBuf,
        expected: PathBuf,
    },
    /// `/proc/<pid>/status` reports a non-zero `TracerPid:` — a
    /// debugger (or ptrace-capable controller) is attached, so the
    /// bytes on disk no longer reflect the running code. Refuse the
    /// connection rather than vend a credential the attacker can lift
    /// out of the traced process's memory.
    #[error("peer pid {pid} is being traced by pid {tracer_pid}")]
    TracerAttached { pid: i32, tracer_pid: i32 },
    /// Reading `/proc/<pid>/exe` or `/proc/<pid>/status` failed —
    /// fail-closed so a kernel-level oddity doesn't silently bypass
    /// the pin check.
    #[error("failed reading /proc/{pid}/{what}: {reason}")]
    ProcReadFailed {
        pid: i32,
        what: &'static str,
        reason: String,
    },
    /// `std::fs::read` on the resolved binary path failed — same
    /// fail-closed posture.
    #[error("failed hashing binary at {path:?} (peer pid {pid}): {reason}")]
    BinaryHashFailed {
        pid: i32,
        path: PathBuf,
        reason: String,
    },
}

/// Parse the `TracerPid:` line out of `/proc/<pid>/status` contents.
///
/// Returns `Some(0)` when the process has no debugger attached (the
/// kernel always emits a `TracerPid:` line, value 0 when untraced).
/// Returns `Some(pid)` for any non-zero tracer. Returns `None` when
/// the input has no `TracerPid:` line — caller treats that as a
/// `ProcReadFailed` (malformed `/proc` entry).
///
/// Public so the test suite can exercise the parse logic directly
/// without standing up a traced process.
pub fn parse_tracer_pid(status: &str) -> Option<i32> {
    for line in status.lines() {
        // Linux's /proc/<pid>/status uses tab separation:
        //   "TracerPid:\t0\n"
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            let trimmed = rest.trim();
            if let Ok(n) = trimmed.parse::<i32>() {
                return Some(n);
            }
        }
    }
    None
}

/// Verify the binary on the other end of a peer-cred-attested socket
/// matches the signed binary-pin manifest.
///
/// On Linux:
/// 1. Read `/proc/<pid>/status` and refuse if `TracerPid:` is non-zero
///    (a debugger is attached; the on-disk bytes don't reflect the
///    running code).
/// 2. Read `/proc/<pid>/exe` (a symlink to the running binary).
/// 3. Blake3-hash the binary bytes.
/// 4. Look up the hash in the manifest. Refuse if not found.
/// 5. Verify the resolved absolute path matches the manifest entry's
///    `absolute_path`. Refuse on mismatch.
///
/// On non-Linux (macOS, etc.): no `/proc` filesystem exists. The
/// caller-side broker handlers gracefully degrade via a `tracing::debug!`
/// and a no-op `Ok(…)` return is NOT available here — the caller is
/// expected to skip the check entirely on non-Linux. This function
/// therefore returns a `cfg(not(target_os = "linux"))` stub that
/// surfaces a structured error so the caller cannot accidentally
/// honor a request against an unverified binary.
#[cfg(target_os = "linux")]
pub fn verify_peer_binary(
    pid: i32,
    manifest: &BinaryManifest,
) -> Result<&BinaryManifestEntry, ManifestVerifyError> {
    // (1) TracerPid gate.
    let status_path = format!("/proc/{pid}/status");
    let status_bytes =
        std::fs::read(&status_path).map_err(|e| ManifestVerifyError::ProcReadFailed {
            pid,
            what: "status",
            reason: e.to_string(),
        })?;
    let status =
        std::str::from_utf8(&status_bytes).map_err(|e| ManifestVerifyError::ProcReadFailed {
            pid,
            what: "status",
            reason: format!("not utf8: {e}"),
        })?;
    let tracer_pid =
        parse_tracer_pid(status).ok_or_else(|| ManifestVerifyError::ProcReadFailed {
            pid,
            what: "status",
            reason: "missing TracerPid line".to_string(),
        })?;
    if tracer_pid != 0 {
        return Err(ManifestVerifyError::TracerAttached { pid, tracer_pid });
    }

    // (2) Resolve /proc/<pid>/exe to the running binary's path.
    let exe_link = format!("/proc/{pid}/exe");
    let exe_path =
        std::fs::read_link(&exe_link).map_err(|e| ManifestVerifyError::ProcReadFailed {
            pid,
            what: "exe",
            reason: e.to_string(),
        })?;

    // (3) Hash the on-disk bytes.
    let bytes = std::fs::read(&exe_path).map_err(|e| ManifestVerifyError::BinaryHashFailed {
        pid,
        path: exe_path.clone(),
        reason: e.to_string(),
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes);
    let computed = hex::encode(hasher.finalize().as_bytes());

    // (4) Look up by hash.
    let entry = manifest
        .entries
        .iter()
        .find(|e| {
            e.content_hash
                .strip_prefix("blake3:")
                .unwrap_or(&e.content_hash)
                == computed
        })
        .ok_or_else(|| ManifestVerifyError::HashNotInManifest {
            pid,
            hash: format!("blake3:{computed}"),
        })?;

    // (5) Cross-check path. The manifest's absolute_path is also pinned —
    // a hash match against a binary on an unexpected path is suspicious
    // (the operator may have unpacked a manifest-vetted binary into a
    // different location, in which case the manifest is stale).
    if entry.absolute_path != exe_path {
        return Err(ManifestVerifyError::PathNotInManifest {
            pid,
            actual: exe_path,
            expected: entry.absolute_path.clone(),
        });
    }

    Ok(entry)
}

/// Non-Linux stub. `/proc` is Linux-specific; macOS would need a
/// `proc_pidpath(3)` + `csops`/`csops_audittoken` audit instead. The
/// broker handlers' `cfg(target_os = "linux")` wrapper invokes this
/// function only on Linux; on other targets the caller skips the
/// check entirely with a `tracing::debug!`. Returning a typed error
/// rather than a silent `Ok(…)` keeps the function fail-closed if
/// it were ever called by mistake on a non-Linux build.
#[cfg(not(target_os = "linux"))]
pub fn verify_peer_binary(
    pid: i32,
    _manifest: &BinaryManifest,
) -> Result<&BinaryManifestEntry, ManifestVerifyError> {
    Err(ManifestVerifyError::ProcReadFailed {
        pid,
        what: "exe",
        reason:
            "/proc is not available on this target — caller must gate on cfg(target_os = \"linux\")"
                .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that exercise the on-disk manifest loader / signer / verifier
    // (any test that needs `tempfile`) live in
    // `tests/binary_manifest_loader.rs` as T2 integration tests per the
    // four-tier convention (`.claude/rules/test-tiers.md`). This in-tree
    // module keeps only T1-shape (no-I/O) tests.
    //
    // Anchor: t1_tier_baseline_drained

    #[test]
    fn load_manifest_returns_empty_when_missing() {
        let path = std::path::PathBuf::from("/nonexistent/manifest.toml");
        let m = load_manifest(&path).expect("ok on missing");
        assert!(m.entries.is_empty());
    }

    // -----------------------------------------------------------------
    // ADR 157 §Component 1 — trust-root SET parameterization tests.
    //
    // The parameterized verifier tests (release-only / release+dev /
    // release+N / empty-set) used `tempfile::tempdir` to materialize the
    // signed manifest + sidecar on disk; they were refiled to
    // `tests/binary_manifest_loader.rs` as T2 integration tests.
    //
    // The `parse_trust_roots` parser tests below are pure-string T1
    // tests that legitimately belong in-tree.
    // -----------------------------------------------------------------

    #[test]
    fn parse_trust_roots_empty_returns_empty_vec() {
        // The "operator did not set EMBER_TRUST_ROOTS" path. Prod daemons
        // hit this case; the daemon's startup wiring is responsible for
        // prepending the compiled-in release root afterwards.
        let parsed = parse_trust_roots("").expect("empty parses cleanly");
        assert!(parsed.is_empty());
        let parsed = parse_trust_roots("   ").expect("whitespace-only parses cleanly");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_trust_roots_single_hex_entry() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
        let pk = sk.verifying_key();
        let hex_str = hex::encode(pk.to_bytes());
        let parsed = parse_trust_roots(&hex_str).expect("single hex parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_bytes(), pk.to_bytes());
    }

    #[test]
    fn parse_trust_roots_did_key_prefix_stripped() {
        // ADR 157 example uses `did:key:<hex>`; the prefix is accepted.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key();
        let did_str = format!("did:key:{}", hex::encode(pk.to_bytes()));
        let parsed = parse_trust_roots(&did_str).expect("did:key prefix parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_bytes(), pk.to_bytes());
    }

    #[test]
    fn parse_trust_roots_multi_entry_with_whitespace() {
        let sk1 = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let raw = format!(
            "{} ,  {}",
            hex::encode(sk1.verifying_key().to_bytes()),
            hex::encode(sk2.verifying_key().to_bytes())
        );
        let parsed = parse_trust_roots(&raw).expect("multi-entry parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].to_bytes(), sk1.verifying_key().to_bytes());
        assert_eq!(parsed[1].to_bytes(), sk2.verifying_key().to_bytes());
    }

    #[test]
    fn parse_trust_roots_invalid_hex_surfaces_error() {
        let result = parse_trust_roots(
            "nothex01010101010101010101010101010101010101010101010101010101010101",
        );
        assert!(
            matches!(result, Err(VerifyError::InvalidPubkey(_))),
            "invalid hex must surface InvalidPubkey; got {result:?}"
        );
    }

    #[test]
    fn parse_trust_roots_wrong_length_surfaces_error() {
        let result = parse_trust_roots("abcd");
        assert!(
            matches!(result, Err(VerifyError::InvalidPubkey(_))),
            "wrong-length entry must surface InvalidPubkey; got {result:?}"
        );
    }

    #[test]
    fn parse_trust_roots_trailing_comma_skipped() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let raw = format!("{},", hex::encode(sk.verifying_key().to_bytes()));
        let parsed = parse_trust_roots(&raw).expect("trailing comma parses");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn duplicate_release_root_from_operator_channel_is_not_operator_posture() {
        let release = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let dev = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        let mut trust_roots = vec![release];

        let appended =
            append_unique_operator_trust_roots(&mut trust_roots, vec![release, dev, dev]);

        assert_eq!(appended, 1, "only the non-release dev root is appended");
        assert_eq!(trust_roots, vec![release, dev]);

        let records = build_trust_root_records(&trust_roots, appended);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].source, TrustRootSource::Release);
        assert_eq!(records[1].source, TrustRootSource::Operator);
    }

    // -----------------------------------------------------------------
    // lookup + channel tests
    // -----------------------------------------------------------------

    fn fixture_bundled_entry(tool: &str) -> BinaryManifestEntry {
        BinaryManifestEntry {
            tool_name: tool.to_string(),
            version: "1.0.0".to_string(),
            content_hash: "blake3:abc123".to_string(),
            absolute_path: bundled_install_dir().join(tool),
            installed_at: 1735689600,
            publisher: "did:emberlink".to_string(),
            channel: BinaryDistributionChannel::Bundled,
        }
    }

    #[test]
    fn cohort_a_constructs_covers_v030_friendly_drop_tools() {
        // v0.3.0 ships 3 tools (gh/git/kubectl) — the
        // 3 with daemon-side classifiers. npm/docker/wrangler/pulumi
        // defer to v0.3.1 (with proper classifiers) or v0.4. ADR 120 §8 Touch-1
        // prompt names git push only — friendly drop covered.
        assert_eq!(COHORT_A_CONSTRUCTS.len(), 3);
        assert!(is_cohort_a_construct("ember-gh"));
        assert!(is_cohort_a_construct("ember-git"));
        assert!(is_cohort_a_construct("ember-kubectl"));
        assert!(!is_cohort_a_construct("ember-npm"));
        assert!(!is_cohort_a_construct("ember-docker"));
        assert!(!is_cohort_a_construct("ember-wrangler"));
        assert!(!is_cohort_a_construct("ember-pulumi"));
        assert!(!is_cohort_a_construct("ember-rogue"));
    }

    #[test]
    fn bundled_runtime_manifest_candidates_keep_custom_scans_to_constructs() {
        let from_dir = PathBuf::from("/tmp/ember-test-binaries");
        let candidates = bundled_runtime_manifest_candidates(&from_dir);
        assert_eq!(candidates.len(), COHORT_A_CONSTRUCTS.len());
        for (tool, (candidate_tool, path)) in COHORT_A_CONSTRUCTS.iter().zip(candidates) {
            assert_eq!(*tool, candidate_tool);
            assert_eq!(path, from_dir.join(tool));
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn bundled_runtime_manifest_candidates_include_platform_rpc_sibling_for_canonical_dir() {
        let candidates = bundled_runtime_manifest_candidates(&bundled_install_dir());
        assert!(
            candidates
                .iter()
                .any(|(tool, path)| *tool == BUNDLED_EMBERD_RPC_TOOL
                    && *path == bundled_emberd_rpc_path()),
            "canonical runtime manifest candidates must include the rpc sibling: {candidates:?}"
        );
    }

    #[test]
    fn lookup_construct_returns_bundled_entry() {
        let manifest = BinaryManifest {
            entries: vec![fixture_bundled_entry("ember-gh")],
        };
        let entry = lookup_construct(&manifest, "ember-gh").expect("found");
        assert_eq!(entry.tool_name, "ember-gh");
        assert_eq!(entry.channel, BinaryDistributionChannel::Bundled);
        assert_eq!(entry.publisher, "did:emberlink");
    }

    #[test]
    fn lookup_construct_not_found_errors() {
        let manifest = BinaryManifest::default();
        let err = lookup_construct(&manifest, "ember-ghost").expect_err("absent");
        assert!(matches!(err, LookupError::NotFound(_)));
    }

    #[test]
    fn lookup_construct_rejects_install_on_demand_in_v030() {
        // v0.3.0 ships only the Bundled channel; defensively refuse
        // InstallOnDemand entries so a forged manifest cannot vend
        // creds against an unsigned third-party binary before v0.4
        // delivers the dynamic-install signing pipeline.
        let mut entry = fixture_bundled_entry("ember-gh");
        entry.channel = BinaryDistributionChannel::InstallOnDemand;
        let manifest = BinaryManifest {
            entries: vec![entry],
        };
        let err = lookup_construct(&manifest, "ember-gh").expect_err("rejected");
        assert!(matches!(err, LookupError::UnsupportedChannel { .. }));
    }

    // `channel_defaults_to_bundled_for_legacy_manifests` moved to
    // `tests/binary_manifest_loader.rs` (T2) — it needed `NamedTempFile`
    // to exercise the serde `default` path against an on-disk TOML.

    #[test]
    fn bundled_install_dir_is_canonical_path() {
        // Stable contract — the v0.3.0 release pipeline writes binaries
        // into this directory; changing it requires a coordinated
        // pipeline + ADR 124 §7 amendment.
        assert_eq!(
            bundled_install_dir(),
            PathBuf::from("/usr/local/lib/ember/binaries")
        );
    }

    // -----------------------------------------------------------------
    // Peer binary
    // pinning gate. The broker handlers refuse a request whose peer
    // binary (resolved via /proc/<pid>/exe + blake3) is not in the
    // signed manifest, or whose process is being traced.
    // -----------------------------------------------------------------

    /// `parse_tracer_pid` correctly extracts the value from a typical
    /// `/proc/<pid>/status` snippet. Production-shape input is tab-
    /// separated; the parser must accept it.
    #[test]
    fn parse_tracer_pid_zero_when_untraced() {
        let sample =
            "Name:\tbash\nState:\tS (sleeping)\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_tracer_pid(sample), Some(0));
    }

    /// `parse_tracer_pid` returns the non-zero tracer pid when a
    /// debugger is attached. Broker handler maps this to `-32008`.
    #[test]
    fn parse_tracer_pid_nonzero_when_traced() {
        let sample = "Name:\ttarget\nTracerPid:\t12345\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_tracer_pid(sample), Some(12345));
    }

    /// `parse_tracer_pid` returns `None` when the input has no
    /// `TracerPid:` line at all — caller treats this as a
    /// `ProcReadFailed` rather than a "no tracer" success.
    #[test]
    fn parse_tracer_pid_returns_none_when_line_missing() {
        let sample = "Name:\tbash\nState:\tS (sleeping)\n";
        assert_eq!(parse_tracer_pid(sample), None);
    }

    /// Failing-test contract from the brief —
    /// `verify_peer_binary_refuses_unmanifested_hash`. The peer pid
    /// resolves to a real binary on disk but the manifest contains
    /// no entry for its hash; `verify_peer_binary` must refuse.
    ///
    /// Uses `/proc/self` so the lookup against /proc itself
    /// succeeds; the manifest is intentionally empty so the
    /// hash-not-in-manifest branch fires.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_peer_binary_refuses_unmanifested_hash() {
        let my_pid = std::process::id() as i32;
        let manifest = BinaryManifest::default();
        let err = verify_peer_binary(my_pid, &manifest).expect_err("must refuse");
        match err {
            ManifestVerifyError::HashNotInManifest { pid, hash } => {
                assert_eq!(pid, my_pid);
                assert!(
                    hash.starts_with("blake3:"),
                    "hash must be blake3-prefixed, got: {hash}"
                );
            }
            other => panic!("expected HashNotInManifest, got {other:?}"),
        }
    }

    /// Companion: manifest contains the peer binary's hash but
    /// its `absolute_path` disagrees with what `/proc/<pid>/exe`
    /// resolves to. The peer binary's path is also pinned, so this
    /// path-mismatch surfaces as `PathNotInManifest` rather than a
    /// happy-path Ok.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_peer_binary_refuses_unmanifested_path() {
        let my_pid = std::process::id() as i32;
        // Hash the running test binary so the hash lookup succeeds.
        let exe_path =
            std::fs::read_link(format!("/proc/{my_pid}/exe")).expect("/proc/self/exe must resolve");
        let bytes = std::fs::read(&exe_path).expect("read test binary");
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let hash = format!("blake3:{}", hex::encode(hasher.finalize().as_bytes()));

        // Intentional path lie: same hash, wrong absolute_path. The
        // path-cross-check must catch this.
        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "ember-test".to_string(),
                version: "0.0.0".to_string(),
                content_hash: hash,
                absolute_path: PathBuf::from("/nonexistent/decoy-path"),
                installed_at: 0,
                publisher: "did:emberlink".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };

        let err = verify_peer_binary(my_pid, &manifest).expect_err("must refuse");
        match err {
            ManifestVerifyError::PathNotInManifest {
                pid,
                actual,
                expected,
            } => {
                assert_eq!(pid, my_pid);
                assert_eq!(actual, exe_path);
                assert_eq!(expected, PathBuf::from("/nonexistent/decoy-path"));
            }
            other => panic!("expected PathNotInManifest, got {other:?}"),
        }
    }

    /// Happy path: manifest contains the peer binary's hash AND the
    /// resolved `/proc/<pid>/exe` path matches. `verify_peer_binary`
    /// returns the matched entry.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_peer_binary_accepts_manifested_binary() {
        let my_pid = std::process::id() as i32;
        let exe_path =
            std::fs::read_link(format!("/proc/{my_pid}/exe")).expect("/proc/self/exe must resolve");
        let bytes = std::fs::read(&exe_path).expect("read test binary");
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        let hash = format!("blake3:{}", hex::encode(hasher.finalize().as_bytes()));

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "ember-test".to_string(),
                version: "0.0.0".to_string(),
                content_hash: hash,
                absolute_path: exe_path.clone(),
                installed_at: 0,
                publisher: "did:emberlink".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };

        let entry = verify_peer_binary(my_pid, &manifest).expect("happy path");
        assert_eq!(entry.tool_name, "ember-test");
        assert_eq!(entry.absolute_path, exe_path);
    }

    /// Failing-test contract from the brief —
    /// `verify_peer_binary_refuses_traced_process`. The brief notes
    /// this is hard to exercise end-to-end without a debugger, so we
    /// drive the parse logic directly (`parse_tracer_pid`) which is
    /// the load-bearing branch inside `verify_peer_binary`.
    #[test]
    fn verify_peer_binary_refuses_traced_process() {
        // The TracerPid parse path is exactly what `verify_peer_binary`
        // calls; a non-zero return becomes `ManifestVerifyError::TracerAttached`.
        let traced_status = "Name:\ttarget\nState:\tt (tracing stop)\nTracerPid:\t12345\nUid:\t1000\t1000\t1000\t1000\n";
        let untraced_status =
            "Name:\tbash\nState:\tS (sleeping)\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_tracer_pid(traced_status), Some(12345));
        assert_eq!(parse_tracer_pid(untraced_status), Some(0));
    }

    /// `verify_peer_binary` against a clearly-impossible pid (no such
    /// process) surfaces a structured `ProcReadFailed` rather than
    /// panicking. Fail-closed posture — kernel-level oddities must
    /// never silently bypass the pin check.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_peer_binary_fail_closed_on_missing_proc_entry() {
        // PID 2^31 - 1 is far beyond /proc/sys/kernel/pid_max in
        // practice; no process has this pid.
        let bogus_pid = i32::MAX;
        let manifest = BinaryManifest::default();
        let err = verify_peer_binary(bogus_pid, &manifest).expect_err("must fail");
        match err {
            ManifestVerifyError::ProcReadFailed { pid, what, .. } => {
                assert_eq!(pid, bogus_pid);
                assert_eq!(what, "status");
            }
            other => panic!("expected ProcReadFailed, got {other:?}"),
        }
    }
}
