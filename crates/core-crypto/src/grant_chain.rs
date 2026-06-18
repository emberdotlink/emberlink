// NOTE: biscuit-auth was evaluated for this module per ADR 073 §"Crypto
// provider." Decision: fall back to raw Ed25519 (the ADR's documented
// escape hatch). Rationale:
//
// 1. `biscuit-auth` signs its own `Biscuit` token format — the signing
//    surface is not "sign arbitrary bytes with a known Ed25519 keypair."
//    Adopting it would force the typed `Block` payload to be marshalled
//    into Biscuit's opaque block format, then un-marshalled on verify.
//    `SignedBlock` already exposes `pubkey_next` (hex Ed25519) and
//    `signature` (hex Ed25519) as first-class fields — the on-wire shape
//    we want *is* raw Ed25519 with the biscuit-style chain invariant.
// 2. ADR 073 explicitly names this fallback: "the escape hatch is a
//    minimal `ed25519-dalek`-backed chain — still not hand-rolled
//    cryptography, just a lighter wrapper."
// 3. `core-crypto` already depends on `ed25519-dalek` for every other
//    signature in the system. Adding `biscuit-auth` would double the
//    cryptographic surface area for zero marginal security — the chain
//    attenuation invariant is enforced by the *chaining rule*
//    ("block N's signature is verified by block N-1's pubkey_next" AND
//    "the predecessor key is bound INSIDE the signed message"), which we
//    implement here identically to biscuit's rule.
// 4. Strategic wedge for the Grant Warden category (ADR 072) is
//    persona + HITL-lifecycle + live view, not which Ed25519 wrapper
//    ships the chain.
//
// SECURITY INVARIANT (C1 fix, security/c1-h1-h3 PR — v0.3.0 pre-release).
// The signature MUST cover the successor's `pubkey_next` bytes (and, for
// block 0, the persona root's public-key bytes). Pre-fix the signature
// covered only `chain_msg(block.canonical_encode())` and `pubkey_next`
// was a sibling field — a holder of any valid chain prefix could swap
// the tail key and append a widening block that `verify_chain` would
// accept. Real Biscuit v2 signs `(block_data ‖ next_key)` for exactly
// this reason. The signed-message construction now matches that shape
// via [`chain_block_zero_msg`] and [`chain_appended_msg`] below.
//
// If/when binary-encoded Biscuit tokens are needed for wire interop
// with external verifiers, add a `to_biscuit_token(...)` adapter that
// emits an equivalent token — it does not require changing the on-disk
// `SignedBlock` format.

use crate::DOMAIN_GRANT_CHAIN;
use core_grant_types::{Block, SignedBlock};
use core_types::CanonicalEncode;
use ed25519_dalek::{Signature as DalekSignature, Signer as DalekSigner, SigningKey, VerifyingKey};
use getrandom::fill as os_fill;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn chain_msg(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN_GRANT_CHAIN.len() + 2 + payload.len());
    msg.extend_from_slice(DOMAIN_GRANT_CHAIN);
    msg.extend_from_slice(b"||");
    msg.extend_from_slice(payload);
    msg
}

/// Length-prefixed concatenation. Each component is prefixed with its
/// big-endian u32 length so the resulting byte string is unambiguously
/// decomposable — there is no parse path that could mistake the boundary
/// between two adjacent components for a payload byte.
///
/// Used by [`chain_block_zero_msg`] and [`chain_appended_msg`] to bind
/// `pubkey_next` (and, for block 0, the root pubkey) into the signed
/// payload so a holder of any valid chain prefix cannot swap the tail
/// key and append a widening block — C1 fix.
fn len_prefixed_concat(components: &[&[u8]]) -> Vec<u8> {
    let total: usize = components.iter().map(|c| 4 + c.len()).sum();
    let mut out = Vec::with_capacity(total);
    for c in components {
        out.extend_from_slice(&(c.len() as u32).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// Build the canonical signed-message bytes for block 0.
///
/// Binds `block.canonical_encode()`, the successor's `pubkey_next` bytes,
/// and the persona root pubkey bytes — so flipping any of the three
/// without re-signing breaks verification. The root-pubkey binding makes
/// "splice a forged block-0 into a chain rooted at a different persona"
/// fail closed: the message any honest signer signed under root A cannot
/// re-verify under root B.
fn chain_block_zero_msg(
    block_canonical: &[u8],
    pubkey_next: &[u8; 32],
    root_pubkey: &[u8; 32],
) -> Vec<u8> {
    chain_msg(&len_prefixed_concat(&[
        block_canonical,
        pubkey_next,
        root_pubkey,
    ]))
}

/// Build the canonical signed-message bytes for an appended block (N≥1).
///
/// Binds `block.canonical_encode()` and the successor's `pubkey_next`
/// bytes. The signer is the previous block's `pubkey_next` private half,
/// so the predecessor key is already cryptographically pinned by the
/// chain rule; only the successor needs explicit binding here.
fn chain_appended_msg(block_canonical: &[u8], pubkey_next: &[u8; 32]) -> Vec<u8> {
    chain_msg(&len_prefixed_concat(&[block_canonical, pubkey_next]))
}

/// Errors from the grant-chain signing / verification layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A key string or signature hex could not be parsed.
    InvalidEncoding(String),
    /// A signature did not verify against the claimed public key.
    SignatureMismatch {
        /// 0-indexed position of the block whose signature failed to verify.
        block_index: usize,
    },
    /// Block 0 was signed under a root key that does not match the persona's
    /// declared root public key.
    RootKeyMismatch,
    /// The chain was empty — every grant must carry at least one block.
    EmptyChain,
    /// A block carries the pre-Cycle-2 `"unsigned-phase1"` placeholder in
    /// either `signature` or `pubkey_next`. These strings were emitted by
    /// pre-migration code paths (`synthesize_access_grant`,
    /// `access_grant_from_statements`) that could not reach persona root
    /// keys. Authorize paths MUST reject them explicitly — the placeholder
    /// is not a valid signature and silently skipping it would defeat the
    /// whole chain.
    ChainUnsigned {
        /// 0-indexed position of the block carrying the placeholder.
        block_index: usize,
    },
    /// Internal invariant violation (would indicate a bug in callers).
    Internal(&'static str),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding(detail) => write!(f, "invalid encoding: {detail}"),
            Self::SignatureMismatch { block_index } => {
                write!(f, "signature verification failed at block {block_index}")
            }
            Self::RootKeyMismatch => {
                write!(
                    f,
                    "block 0 signature does not verify against the declared root public key"
                )
            }
            Self::EmptyChain => write!(f, "grant chain must contain at least one block"),
            Self::ChainUnsigned { block_index } => write!(
                f,
                "block {block_index} carries pre-migration 'unsigned-phase1' placeholder; refusing to authorize"
            ),
            Self::Internal(detail) => write!(f, "internal chain error: {detail}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Literal placeholder string emitted by pre-Cycle-2 code paths that could
/// not yet access persona root keys (`ember-daemon/src/grant.rs`). Exposed
/// so callers can detect pre-migration grants explicitly.
pub const UNSIGNED_PHASE1_PLACEHOLDER: &str = "unsigned-phase1";

/// Returns true if `sb` carries the pre-Cycle-2 placeholder in either the
/// signature or `pubkey_next` field. Used by `verify_chain` to reject
/// pre-migration grants up front with a structured error rather than
/// returning `SignatureMismatch` (which would be a lie — nothing was
/// signed at all).
fn is_unsigned_phase1(sb: &SignedBlock) -> bool {
    sb.signature == UNSIGNED_PHASE1_PLACEHOLDER || sb.pubkey_next == UNSIGNED_PHASE1_PLACEHOLDER
}

const PUBKEY_HEX_LEN: usize = 64; // 32 bytes * 2 hex chars

/// A freshly minted ephemeral keypair that signs the next appended block.
///
/// When a block is signed, a new `pubkey_next` keypair is generated. The
/// public half goes into the `SignedBlock.pubkey_next` field (in hex); the
/// private half must be retained by whoever holds the right to append the
/// next block in the chain. Losing the private half freezes the chain — no
/// further attenuation can be applied.
///
/// Callers MUST persist `secret_hex` securely (the same keystore used for
/// other signing keys); it is a public field precisely so the holder can
/// persist it.
///
/// # Secret hygiene
///
/// - `Debug` is **manually implemented** to redact `secret_hex`, so a
///   reflexive `format!("{kp:?}")` — or a derived `Debug` on a containing
///   type such as [`GrantChainLink`] — prints `secret_hex: <redacted>`
///   rather than the raw key material.
/// - `Zeroize` + `ZeroizeOnDrop` scrub both `String`s' backing bytes when the
///   value goes out of scope (or on an explicit `zeroize()`). Deriving
///   `Zeroize` alone does **not** wipe on drop — `ZeroizeOnDrop` is what
///   installs the `Drop` impl. (The sibling [`RootKeyPair`] derives both.)
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PubkeyNextKeyPair {
    pub public_hex: String,
    pub secret_hex: String,
}

impl std::fmt::Debug for PubkeyNextKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubkeyNextKeyPair")
            .field("public_hex", &self.public_hex)
            .field("secret_hex", &"<redacted>")
            .finish()
    }
}

impl PubkeyNextKeyPair {
    /// Mint a fresh ephemeral keypair for the chain's tail.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        os_fill(&mut seed).expect("OS entropy failure");
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_hex = hex::encode(verifying_key.to_bytes());
        let secret_hex = hex::encode(seed);
        seed.zeroize();
        Self {
            public_hex,
            secret_hex,
        }
    }

    /// Rebuild from hex strings. Rejects malformed encodings eagerly.
    pub fn from_hex(
        public_hex: impl Into<String>,
        secret_hex: impl Into<String>,
    ) -> Result<Self, ChainError> {
        let public_hex = public_hex.into();
        let secret_hex = secret_hex.into();
        let _ = decode_secret(&secret_hex)?;
        let _ = decode_pubkey(&public_hex)?;
        Ok(Self {
            public_hex,
            secret_hex,
        })
    }

    fn signing_key(&self) -> Result<SigningKey, ChainError> {
        let secret = decode_secret(&self.secret_hex)?;
        Ok(SigningKey::from_bytes(&secret))
    }
}

/// The persona's root signing key material, used to sign block 0.
///
/// Thin wrapper over the `LocalKeyPair` already in the keystore — this type
/// keeps the grant-chain API legible without forcing callers to reach into
/// `core_crypto::LocalKeyPair` directly.
///
/// # Secret hygiene (F-03)
///
/// - The secret half is a **private field**. There is no accessor. Signing
///   goes through `signing_key()` (crate-private) or the public
///   [`RootKeyPair::from_hex`] constructor; the raw hex never escapes this
///   module.
/// - `Debug` is **manually implemented** to redact the secret — a reflexive
///   `tracing::debug!(?root, ...)` or `format!("{root:?}")` prints
///   `RootKeyPair { public: <hex>, secret: <redacted> }` and nothing more.
/// - `Zeroize` + `ZeroizeOnDrop` scrub the secret `String`'s backing bytes
///   when the value goes out of scope (or on explicit `zeroize()`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKeyPair {
    public_hex: String,
    secret_hex: String,
}

impl std::fmt::Debug for RootKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootKeyPair")
            .field("public", &self.public_hex)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl RootKeyPair {
    pub fn from_hex(
        public_hex: impl Into<String>,
        secret_hex: impl Into<String>,
    ) -> Result<Self, ChainError> {
        let public_hex = public_hex.into();
        let secret_hex = secret_hex.into();
        let _ = decode_secret(&secret_hex)?;
        let _ = decode_pubkey(&public_hex)?;
        Ok(Self {
            public_hex,
            secret_hex,
        })
    }

    /// The public half of the root key, in raw hex (no `ed25519:` prefix).
    /// Safe to log — public keys are not secret.
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// The public half as raw 32 bytes, ready for `verify_chain`'s
    /// `root_pubkey` argument. Convenience over `hex::decode(kp.public_hex())`
    /// so callers don't have to depend on the `hex` crate directly.
    pub fn public_bytes(&self) -> Result<[u8; 32], ChainError> {
        decode_pubkey(&self.public_hex)
    }

    fn signing_key(&self) -> Result<SigningKey, ChainError> {
        let secret = decode_secret(&self.secret_hex)?;
        Ok(SigningKey::from_bytes(&secret))
    }
}

/// Output of `sign_block_zero` — the signed block plus the secret half of
/// the freshly-minted `pubkey_next` keypair. Callers MUST persist
/// `pubkey_next_secret` to sign any later appended block.
#[derive(Debug, Clone)]
pub struct SignedBlockOutput {
    pub signed: SignedBlock,
    pub pubkey_next_secret: PubkeyNextKeyPair,
}

/// Sign block 0 of a grant chain under the persona's root key.
///
/// Generates a fresh `pubkey_next` keypair and signs `chain_msg` over the
/// length-prefixed concatenation of `block.canonical_encode()`,
/// `pubkey_next` bytes, and the root pubkey bytes. The root-pubkey
/// binding prevents "splice a forged block 0 into a chain rooted at a
/// different persona"; the `pubkey_next` binding prevents tail-key swap +
/// widening append (C1 fix — pre-fix the signature covered only the
/// block payload and `pubkey_next` was a sibling field).
///
/// Returns both the resulting `SignedBlock` and the `pubkey_next` secret —
/// the caller must persist the secret to later append block 1.
pub fn sign_block_zero(
    root_key: &RootKeyPair,
    block: &Block,
) -> Result<SignedBlockOutput, ChainError> {
    let root_signing = root_key.signing_key()?;
    let root_pubkey_bytes = root_key.public_bytes()?;
    let pubkey_next = PubkeyNextKeyPair::generate();
    let pubkey_next_bytes = decode_pubkey(&pubkey_next.public_hex)?;
    let payload = block.canonical_encode();
    let signature = root_signing.sign(&chain_block_zero_msg(
        &payload,
        &pubkey_next_bytes,
        &root_pubkey_bytes,
    ));
    Ok(SignedBlockOutput {
        signed: SignedBlock {
            block: block.clone(),
            pubkey_next: pubkey_next.public_hex.clone(),
            signature: hex::encode(signature.to_bytes()),
        },
        pubkey_next_secret: pubkey_next,
    })
}

/// Sign a later block in the chain, using the previous block's
/// `pubkey_next` private key as the signer.
///
/// The signature covers `chain_msg` over the length-prefixed
/// concatenation of `block.canonical_encode()` and the successor's
/// `pubkey_next` bytes (C1 fix — previously only the block payload was
/// signed, leaving `pubkey_next` swap-and-append-able). The predecessor
/// key is already cryptographically pinned by the chain rule (this
/// signature is verifiable only by the previous `pubkey_next`'s public
/// half), so it is not duplicated in the message.
///
/// The caller is responsible for pairing the right `prev_pubkey_next`
/// secret with the right predecessor block. This function does not
/// re-verify the whole chain — use `verify_chain` for that.
pub fn sign_appended_block(
    prev_pubkey_next: &PubkeyNextKeyPair,
    block: &Block,
) -> Result<SignedBlockOutput, ChainError> {
    let prev_signing = prev_pubkey_next.signing_key()?;
    let pubkey_next = PubkeyNextKeyPair::generate();
    let pubkey_next_bytes = decode_pubkey(&pubkey_next.public_hex)?;
    let payload = block.canonical_encode();
    let signature = prev_signing.sign(&chain_appended_msg(&payload, &pubkey_next_bytes));
    Ok(SignedBlockOutput {
        signed: SignedBlock {
            block: block.clone(),
            pubkey_next: pubkey_next.public_hex.clone(),
            signature: hex::encode(signature.to_bytes()),
        },
        pubkey_next_secret: pubkey_next,
    })
}

/// Verify a complete grant chain.
///
/// - Block 0's signature is verified against `root_pubkey` (the persona's
///   declared root Ed25519 public key, 32 raw bytes). The signed message
///   covers the block payload, the successor's `pubkey_next`, and the
///   root pubkey bytes (C1 fix — see [`chain_block_zero_msg`]).
/// - Each subsequent block is verified against the previous `SignedBlock`'s
///   `pubkey_next`. The signed message covers the block payload and the
///   successor's `pubkey_next` (see [`chain_appended_msg`]).
///
/// Canonical-encodes each block with `CanonicalEncode` — any tampering of
/// block payload, reorder of blocks, or swap of any block's
/// `pubkey_next` breaks the chain.
pub fn verify_chain(blocks: &[SignedBlock], root_pubkey: &[u8]) -> Result<(), ChainError> {
    if blocks.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    // Reject pre-Cycle-2 placeholders explicitly. These strings are not
    // valid hex, so the downstream `decode_pubkey` / `hex::decode` paths
    // would return a generic `InvalidEncoding` — callers would have to
    // string-match on the error to tell "never signed" from "corrupt hex."
    // Surface it as a structured error instead so authorize paths can
    // enforce a clean reject.
    for (index, sb) in blocks.iter().enumerate() {
        if is_unsigned_phase1(sb) {
            return Err(ChainError::ChainUnsigned { block_index: index });
        }
    }

    let root_pubkey_bytes: [u8; 32] = root_pubkey
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding("root pubkey must be 32 bytes".into()))?;
    let root_verifying = VerifyingKey::from_bytes(&root_pubkey_bytes)
        .map_err(|err| ChainError::InvalidEncoding(format!("invalid root pubkey: {err}")))?;

    // Block 0 — signed by root; signature binds root_pubkey + pubkey_next.
    verify_block_zero(&blocks[0], &root_verifying, &root_pubkey_bytes).map_err(|err| {
        // Remap generic signature-mismatch at block 0 to a more precise
        // root-key-mismatch error so callers can distinguish "chain forged
        // against a different persona" from "chain internally inconsistent."
        if matches!(err, ChainError::SignatureMismatch { block_index: 0 }) {
            ChainError::RootKeyMismatch
        } else {
            err
        }
    })?;

    // Blocks 1..N — each signed by the previous block's pubkey_next;
    // signature binds this block's pubkey_next.
    for i in 1..blocks.len() {
        let prev_pubkey_hex = &blocks[i - 1].pubkey_next;
        let prev_pubkey_bytes = decode_pubkey(prev_pubkey_hex)?;
        let prev_verifying = VerifyingKey::from_bytes(&prev_pubkey_bytes).map_err(|err| {
            ChainError::InvalidEncoding(format!("invalid pubkey_next at block {}: {err}", i - 1))
        })?;
        verify_appended(&blocks[i], &prev_verifying, i)?;
    }
    Ok(())
}

/// Verify block 0 under the root pubkey, binding both `pubkey_next` and
/// the root pubkey into the signed message.
fn verify_block_zero(
    sb: &SignedBlock,
    signer_pubkey: &VerifyingKey,
    root_pubkey_bytes: &[u8; 32],
) -> Result<(), ChainError> {
    let signature = decode_signature(&sb.signature)?;
    let pubkey_next_bytes = decode_pubkey(&sb.pubkey_next)?;
    let payload = sb.block.canonical_encode();
    signer_pubkey
        .verify_strict(
            &chain_block_zero_msg(&payload, &pubkey_next_bytes, root_pubkey_bytes),
            &signature,
        )
        .map_err(|_| ChainError::SignatureMismatch { block_index: 0 })
}

/// Verify an appended block (N≥1) under the previous block's
/// `pubkey_next`, binding this block's `pubkey_next` into the signed
/// message.
fn verify_appended(
    sb: &SignedBlock,
    signer_pubkey: &VerifyingKey,
    block_index: usize,
) -> Result<(), ChainError> {
    let signature = decode_signature(&sb.signature)?;
    let pubkey_next_bytes = decode_pubkey(&sb.pubkey_next)?;
    let payload = sb.block.canonical_encode();
    signer_pubkey
        .verify_strict(
            &chain_appended_msg(&payload, &pubkey_next_bytes),
            &signature,
        )
        .map_err(|_| ChainError::SignatureMismatch { block_index })
}

fn decode_signature(hex_str: &str) -> Result<DalekSignature, ChainError> {
    let sig_bytes = hex::decode(hex_str)
        .map_err(|err| ChainError::InvalidEncoding(format!("invalid signature hex: {err}")))?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding("signature must be 64 bytes".into()))?;
    Ok(DalekSignature::from_bytes(&sig_array))
}

fn decode_secret(hex_str: &str) -> Result<[u8; 32], ChainError> {
    let bytes = hex::decode(hex_str)
        .map_err(|err| ChainError::InvalidEncoding(format!("invalid secret hex: {err}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding("secret key must be 32 bytes".into()))
}

fn decode_pubkey(hex_str: &str) -> Result<[u8; 32], ChainError> {
    if hex_str.len() != PUBKEY_HEX_LEN {
        return Err(ChainError::InvalidEncoding(format!(
            "public key hex must be {PUBKEY_HEX_LEN} chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|err| ChainError::InvalidEncoding(format!("invalid pubkey hex: {err}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding("public key must be 32 bytes".into()))
}

/// Extract raw 32-byte Ed25519 root public key bytes from an `ed25519:`-
/// prefixed hex encoding — the format the rest of the system uses for
/// `RootRecord.active_key.public_key`.
///
/// Convenience for authorize-path callers that have a
/// `PersonaRecord`+`RootRecord` and need the raw bytes to pass to
/// `verify_chain`.
pub fn root_pubkey_bytes_from_ed25519_hex(hex: &str) -> Result<[u8; 32], ChainError> {
    let body = hex
        .strip_prefix("ed25519:")
        .ok_or_else(|| ChainError::InvalidEncoding("expected ed25519: prefix".into()))?;
    let bytes = ::hex::decode(body)
        .map_err(|err| ChainError::InvalidEncoding(format!("invalid root pubkey hex: {err}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding("root pubkey must be 32 bytes".into()))
}

/// Extract a `RootKeyPair` from a `LocalKeyPair` — the usual path for
/// callers who already have the persona's root key loaded via the
/// existing keystore.
pub fn root_key_from_local_key_pair(
    key_pair: &crate::LocalKeyPair,
) -> Result<RootKeyPair, ChainError> {
    if key_pair.algorithm != core_principals::KeyAlgorithm::Ed25519 {
        return Err(ChainError::InvalidEncoding(
            "root key must be Ed25519".into(),
        ));
    }
    // `LocalKeyPair` stores both halves prefixed (`ed25519:` / `ed25519-secret:`).
    let public_hex = strip_prefix(&key_pair.public_key, "ed25519:")?;
    let secret_hex = strip_prefix(&key_pair.private_key, "ed25519-secret:")?;
    RootKeyPair::from_hex(public_hex, secret_hex)
}

fn strip_prefix<'a>(value: &'a str, prefix: &str) -> Result<&'a str, ChainError> {
    value.strip_prefix(prefix).ok_or_else(|| {
        ChainError::InvalidEncoding(format!("expected prefix '{prefix}' on key encoding"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_grant_types::{ResourceSelector, ResourceType, Statement, Usage};
    use core_principals::KeyAlgorithm;

    fn fresh_root_keypair() -> (RootKeyPair, [u8; 32]) {
        make_root_keypair(42)
    }

    fn make_root_keypair(fill: u8) -> (RootKeyPair, [u8; 32]) {
        let seed = [fill; 32];
        let signing = SigningKey::from_bytes(&seed);
        let pubkey_bytes = signing.verifying_key().to_bytes();
        let pair = RootKeyPair::from_hex(hex::encode(pubkey_bytes), hex::encode(seed)).unwrap();
        (pair, pubkey_bytes)
    }

    fn sample_block(sid: &str, issued_at: u64) -> Block {
        Block {
            statements: vec![Statement {
                sid: sid.into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".into()],
                resource: ResourceSelector::Exact {
                    value: "obj-github-token".into(),
                },
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
                can_delegate: None,
            }],
            nbf: None,
            expires_at: None,
            issued_by: "persona_work".into(),
            issued_at,
            approval: None,
            note: None,
        }
    }

    #[test]
    fn sign_block_zero_then_verify_chain_succeeds() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let block = sample_block("Stmt0", 10);
        let out = sign_block_zero(&root, &block).unwrap();

        assert_eq!(out.signed.block, block);
        assert_eq!(out.signed.pubkey_next, out.pubkey_next_secret.public_hex);
        verify_chain(std::slice::from_ref(&out.signed), &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn tampered_block_zero_fails_verify() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let block = sample_block("Stmt0", 10);
        let mut out = sign_block_zero(&root, &block).unwrap();

        // Flip one byte of the block payload after signing — canonical
        // encoding changes, so signature no longer verifies.
        out.signed.block.issued_at = 999;
        let err = verify_chain(&[out.signed], &root_pubkey_bytes).unwrap_err();
        assert_eq!(err, ChainError::RootKeyMismatch);
    }

    #[test]
    fn three_block_delegation_chain_verifies() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        let b1 = sample_block("Stmt1", 20);
        let out1 = sign_appended_block(&out0.pubkey_next_secret, &b1).unwrap();

        let b2 = sample_block("Stmt2", 30);
        let out2 = sign_appended_block(&out1.pubkey_next_secret, &b2).unwrap();

        let chain = vec![
            out0.signed.clone(),
            out1.signed.clone(),
            out2.signed.clone(),
        ];
        verify_chain(&chain, &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn reordered_chain_fails_verify() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        let b1 = sample_block("Stmt1", 20);
        let out1 = sign_appended_block(&out0.pubkey_next_secret, &b1).unwrap();

        let b2 = sample_block("Stmt2", 30);
        let out2 = sign_appended_block(&out1.pubkey_next_secret, &b2).unwrap();

        // Swap blocks 1 and 2 — block 2 was signed by out1.pubkey_next, so
        // verifying it against out0.pubkey_next (block position 1) must fail.
        let swapped = vec![out0.signed, out2.signed, out1.signed];
        let err = verify_chain(&swapped, &root_pubkey_bytes).unwrap_err();
        assert_eq!(err, ChainError::SignatureMismatch { block_index: 1 });
    }

    #[test]
    fn empty_chain_rejected() {
        let (_, root_pubkey_bytes) = fresh_root_keypair();
        let err = verify_chain(&[], &root_pubkey_bytes).unwrap_err();
        assert_eq!(err, ChainError::EmptyChain);
    }

    #[test]
    fn wrong_root_pubkey_is_distinguished_from_tampering() {
        let (root_a, _root_a_pubkey) = make_root_keypair(42);
        let (_root_b, root_b_pubkey) = make_root_keypair(43);
        let block = sample_block("Stmt0", 10);
        let out = sign_block_zero(&root_a, &block).unwrap();

        // Chain is internally valid but was not signed by root_b.
        let err = verify_chain(std::slice::from_ref(&out.signed), &root_b_pubkey).unwrap_err();
        assert_eq!(err, ChainError::RootKeyMismatch);
    }

    #[test]
    fn tampered_later_block_reports_its_index() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        let b1 = sample_block("Stmt1", 20);
        let mut out1 = sign_appended_block(&out0.pubkey_next_secret, &b1).unwrap();
        out1.signed.block.issued_at = 999;

        let err = verify_chain(&[out0.signed, out1.signed], &root_pubkey_bytes).unwrap_err();
        assert_eq!(err, ChainError::SignatureMismatch { block_index: 1 });
    }

    #[test]
    fn pubkey_next_secret_can_be_persisted_and_restored() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        // Simulate persisting the secret across a daemon restart.
        let restored = PubkeyNextKeyPair::from_hex(
            out0.pubkey_next_secret.public_hex.clone(),
            out0.pubkey_next_secret.secret_hex.clone(),
        )
        .unwrap();

        let b1 = sample_block("Stmt1", 20);
        let out1 = sign_appended_block(&restored, &b1).unwrap();
        verify_chain(&[out0.signed, out1.signed], &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn round_trip_from_local_key_pair() {
        // Build a deterministic LocalKeyPair from a fixed seed so this test
        // does not touch OS entropy (library-crates rule: tests must compile
        // and run identically on host + wasm32-unknown-unknown).
        let seed = [77u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        let local = crate::LocalKeyPair {
            key_id: "key-root-root-a-v1-fixture".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: format!("ed25519:{pubkey_hex}"),
            private_key: format!("ed25519-secret:{}", hex::encode(seed)),
        };
        let root_kp = root_key_from_local_key_pair(&local).unwrap();
        let block = sample_block("Stmt0", 42);
        let out = sign_block_zero(&root_kp, &block).unwrap();

        let root_pubkey_bytes = hex::decode(root_kp.public_hex()).unwrap();
        verify_chain(std::slice::from_ref(&out.signed), &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn invalid_secret_hex_rejected() {
        let err = RootKeyPair::from_hex("ab".repeat(32), "not-hex!").unwrap_err();
        assert!(matches!(err, ChainError::InvalidEncoding(_)));
    }

    #[test]
    fn unsigned_phase1_placeholder_rejected_by_verify_chain() {
        let (_, root_pubkey_bytes) = fresh_root_keypair();
        let placeholder_block = SignedBlock {
            block: sample_block("Stmt0", 10),
            pubkey_next: UNSIGNED_PHASE1_PLACEHOLDER.into(),
            signature: UNSIGNED_PHASE1_PLACEHOLDER.into(),
        };
        let err = verify_chain(&[placeholder_block], &root_pubkey_bytes).unwrap_err();
        assert_eq!(err, ChainError::ChainUnsigned { block_index: 0 });
    }

    #[test]
    fn unsigned_phase1_placeholder_in_tail_rejected() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        // A tail block that was never signed (placeholder pubkey_next) must
        // still be rejected even though the prior block is valid.
        let unsigned_tail = SignedBlock {
            block: sample_block("Stmt1", 20),
            pubkey_next: UNSIGNED_PHASE1_PLACEHOLDER.into(),
            signature: UNSIGNED_PHASE1_PLACEHOLDER.into(),
        };
        let err = verify_chain(&[out0.signed, unsigned_tail], &root_pubkey_bytes).unwrap_err();
        assert_eq!(err, ChainError::ChainUnsigned { block_index: 1 });
    }

    /// F-03: `Debug` on `RootKeyPair` must never leak the secret half.
    /// `format!("{:?}", root)` and `tracing::debug!(?root, ...)` are the
    /// reflexive shapes that would otherwise ship the secret to logs/sinks.
    #[test]
    fn rootkeypair_debug_redacts_secret() {
        let (root, _) = fresh_root_keypair();

        // Keep a copy of the true secret via a round-trip back out of the
        // module: reconstruct a RootKeyPair from the same hex we originally
        // fed `from_hex`. We need the secret string for the anti-leak
        // assertion.
        let seed = [99u8; 32];
        let secret_hex_true = hex::encode(seed);
        let signing = SigningKey::from_bytes(&seed);
        let pub_hex_true = hex::encode(signing.verifying_key().to_bytes());
        let root2 = RootKeyPair::from_hex(pub_hex_true.clone(), secret_hex_true.clone()).unwrap();

        let dbg = format!("{root2:?}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug output must contain redaction marker: {dbg}"
        );
        assert!(
            !dbg.contains(&secret_hex_true),
            "Debug output MUST NOT contain the secret hex: {dbg}"
        );
        // Public half is safe to include and useful for operator triage.
        assert!(
            dbg.contains(&pub_hex_true),
            "Debug output should include the public hex for triage: {dbg}"
        );

        // Silence unused-warning on `root`: Debug-print it too so this
        // test exercises the generate/construct path as well.
        let _ = format!("{root:?}");
    }

    /// F-03: manual `Zeroize` on `RootKeyPair` scrubs the secret in place.
    /// `ZeroizeOnDrop` runs the same routine at end-of-scope; we cannot
    /// observe post-drop memory portably, so test the explicit path — the
    /// drop behaviour is guaranteed by the derive.
    #[test]
    fn rootkeypair_zeroize_clears_secret() {
        let (mut root, _) = fresh_root_keypair();
        // Baseline: both halves are non-empty hex strings before zeroize.
        assert!(!root.secret_hex.is_empty());
        assert!(!root.public_hex.is_empty());

        root.zeroize();

        // `Zeroize for String` empties the string (length 0), which also
        // wipes the backing buffer. A zeroed `RootKeyPair` has no hex in
        // either field — `signing_key()` would fail if called.
        assert!(
            root.secret_hex.is_empty(),
            "zeroize must empty the secret_hex string"
        );
        assert!(
            root.public_hex.is_empty(),
            "zeroize must empty the public_hex string"
        );
    }

    /// `PubkeyNextKeyPair` `Debug` must never leak `secret_hex`. It is
    /// reachable via the derived `Debug` on [`GrantChainLink`], which holds a
    /// `PubkeyNextKeyPair` — a reflexive `tracing::debug!(?link, ...)` would
    /// otherwise ship the secret to logs/sinks.
    #[test]
    fn pubkeynextkeypair_debug_redacts_secret() {
        let seed = [0x5au8; 32];
        let secret_hex_true = hex::encode(seed);
        let signing = SigningKey::from_bytes(&seed);
        let pub_hex_true = hex::encode(signing.verifying_key().to_bytes());
        let kp =
            PubkeyNextKeyPair::from_hex(pub_hex_true.clone(), secret_hex_true.clone()).unwrap();

        let dbg = format!("{kp:?}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug output must contain redaction marker: {dbg}"
        );
        assert!(
            !dbg.contains(&secret_hex_true),
            "Debug output MUST NOT contain the secret hex: {dbg}"
        );
        assert!(
            dbg.contains(&pub_hex_true),
            "Debug output should include the public hex for triage: {dbg}"
        );
    }

    /// `Zeroize` on `PubkeyNextKeyPair` scrubs the secret in place;
    /// `ZeroizeOnDrop` runs the same routine at end-of-scope. Post-drop memory
    /// is not portably observable, so test the explicit path — the drop
    /// behaviour is guaranteed by the derive. (Before the fix this type derived
    /// `Zeroize` only, and the doc falsely claimed it wiped on drop.)
    #[test]
    fn pubkeynextkeypair_zeroize_clears_secret() {
        let seed = [0x5au8; 32];
        let secret_hex = hex::encode(seed);
        let signing = SigningKey::from_bytes(&seed);
        let pub_hex = hex::encode(signing.verifying_key().to_bytes());
        let mut kp = PubkeyNextKeyPair::from_hex(pub_hex, secret_hex).unwrap();
        assert!(!kp.secret_hex.is_empty());
        assert!(!kp.public_hex.is_empty());

        kp.zeroize();

        assert!(
            kp.secret_hex.is_empty(),
            "zeroize must empty the secret_hex string"
        );
        assert!(
            kp.public_hex.is_empty(),
            "zeroize must empty the public_hex string"
        );
    }

    /// Torsion-point regression: `verify_chain` uses `verify_strict` in the
    /// internal `verify_block_zero` / `verify_appended` helpers, which reject
    /// any block whose signature R component is a torsion point.
    ///
    /// Without `verify_strict`, an attacker could substitute a valid block
    /// signature with a malleable variant (same S, R replaced by R + torsion
    /// point) and the chain would accept both — breaking the uniqueness
    /// invariant required for secure grant revocation and audit log integrity.
    #[test]
    fn verify_chain_rejects_torsion_r_in_signature() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let block = sample_block("Stmt0", 10);
        let mut out = sign_block_zero(&root, &block).unwrap();

        // Replace the signature R component with a known Ed25519 torsion point.
        // Source: ed25519-dalek EIGHT_TORSION[1] — order-8 point, RFC 8032 §5.1.
        let torsion_r_bytes: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];
        let mut sig_bytes = hex::decode(&out.signed.signature).unwrap();
        sig_bytes[..32].copy_from_slice(&torsion_r_bytes);
        out.signed.signature = hex::encode(&sig_bytes);

        let err = verify_chain(&[out.signed], &root_pubkey_bytes).unwrap_err();
        assert_eq!(
            err,
            ChainError::RootKeyMismatch,
            "torsion-R signature must be rejected at block 0"
        );
    }

    #[test]
    fn sign_and_extend_two_blocks_via_persisted_secret_round_trip() {
        // M-3 integration: sign block 0, persist the secret as hex (as
        // emberlink-cli/local_state does), restore it, sign block 1,
        // verify end-to-end. Fails if the persistence shape diverges
        // from `PubkeyNextKeyPair::from_hex`.
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        // Simulate writing to local-state.enc TSV line:
        //   chain_secret <grant_id> <public_hex> <secret_hex>
        let persisted_public = out0.pubkey_next_secret.public_hex.clone();
        let persisted_secret = out0.pubkey_next_secret.secret_hex.clone();

        // ...reload on the next daemon tick.
        let restored = PubkeyNextKeyPair::from_hex(persisted_public, persisted_secret).unwrap();

        let b1 = sample_block("Stmt1", 20);
        let out1 = sign_appended_block(&restored, &b1).unwrap();
        verify_chain(&[out0.signed, out1.signed], &root_pubkey_bytes).unwrap();
    }

    /// **C1 forgery regression** — pubkey_next is part of the signed
    /// payload, so a holder of a valid chain prefix [B0] CANNOT swap
    /// `B0.pubkey_next` to an attacker-controlled key and then sign a
    /// widening appended block with that attacker key. Pre-fix the
    /// signature covered only `block.canonical_encode()`, leaving the
    /// pubkey_next field a sibling that anyone could overwrite — and
    /// `verify_chain([B0', B1])` would accept the result.
    ///
    /// Voids ADR 072's "cryptographically enforced attenuation" claim
    /// pre-fix; verifies it post-fix.
    #[test]
    fn tail_key_swap_plus_append_is_refused() {
        // Build a valid chain [B0] under root R.
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0_block = sample_block("Stmt0", 10);
        let b0 = sign_block_zero(&root, &b0_block).unwrap();

        // Honest sanity check: the chain verifies.
        verify_chain(std::slice::from_ref(&b0.signed), &root_pubkey_bytes).unwrap();

        // Attacker mints a fresh keypair (their own pubkey_next replacement).
        let attacker = PubkeyNextKeyPair::generate();

        // Swap B0.pubkey_next to the attacker-controlled key.
        let mut b0_forged = b0.signed.clone();
        b0_forged.pubkey_next = attacker.public_hex.clone();

        // Sign a widening B1 with the attacker's private key.
        let b1_widened = Block {
            statements: vec![Statement {
                sid: "Forged".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["*".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
                can_delegate: None,
            }],
            nbf: None,
            expires_at: None,
            issued_by: "persona_work".into(),
            issued_at: 99,
            approval: None,
            note: None,
        };
        let b1 = sign_appended_block(&attacker, &b1_widened).unwrap();

        // Post-fix: verify_chain MUST refuse. Pre-fix this returned Ok.
        let err = verify_chain(&[b0_forged, b1.signed], &root_pubkey_bytes).unwrap_err();
        assert!(
            matches!(err, ChainError::RootKeyMismatch)
                || matches!(err, ChainError::SignatureMismatch { block_index: 0 }),
            "tail-key swap + widening append MUST refuse; got {err:?}"
        );
    }

    /// C1 sibling regression: tampering ONLY with `pubkey_next` on a
    /// single-block chain (no appended block) still breaks verification,
    /// because the signed payload binds the successor key.
    #[test]
    fn pubkey_next_swap_alone_invalidates_block_zero() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let block = sample_block("Stmt0", 10);
        let mut out = sign_block_zero(&root, &block).unwrap();

        let attacker = PubkeyNextKeyPair::generate();
        out.signed.pubkey_next = attacker.public_hex.clone();

        let err = verify_chain(&[out.signed], &root_pubkey_bytes).unwrap_err();
        assert_eq!(
            err,
            ChainError::RootKeyMismatch,
            "swapping pubkey_next on block 0 MUST invalidate the signature"
        );
    }

    /// C1 sibling regression: on a multi-block chain, tampering with an
    /// intermediate block's `pubkey_next` (after the chain is built)
    /// invalidates the intermediate block's signature too, because the
    /// signature binds its own pubkey_next.
    #[test]
    fn intermediate_pubkey_next_swap_invalidates_that_block() {
        let (root, root_pubkey_bytes) = fresh_root_keypair();
        let b0 = sample_block("Stmt0", 10);
        let out0 = sign_block_zero(&root, &b0).unwrap();

        let b1 = sample_block("Stmt1", 20);
        let mut out1 = sign_appended_block(&out0.pubkey_next_secret, &b1).unwrap();

        let attacker = PubkeyNextKeyPair::generate();
        out1.signed.pubkey_next = attacker.public_hex.clone();

        let err = verify_chain(&[out0.signed, out1.signed], &root_pubkey_bytes).unwrap_err();
        assert_eq!(
            err,
            ChainError::SignatureMismatch { block_index: 1 },
            "swapping pubkey_next on an appended block MUST invalidate that block's signature"
        );
    }

    /// C1 cross-persona splice defence: a block-0 signature minted under
    /// root_a MUST NOT re-verify under root_b even if all other fields
    /// are identical (because the root pubkey is bound into the message).
    /// This protects against "forge a block 0 against a different persona
    /// root and splice."
    #[test]
    fn block_zero_signature_does_not_re_verify_under_a_different_root() {
        let (root_a, root_a_pubkey) = make_root_keypair(7);
        let (_root_b, root_b_pubkey) = make_root_keypair(8);
        let block = sample_block("Stmt0", 10);
        let out = sign_block_zero(&root_a, &block).unwrap();

        // Sanity: verifies under root_a.
        verify_chain(std::slice::from_ref(&out.signed), &root_a_pubkey).unwrap();

        // Splicing into a chain rooted at root_b MUST fail.
        let err = verify_chain(std::slice::from_ref(&out.signed), &root_b_pubkey).unwrap_err();
        assert_eq!(err, ChainError::RootKeyMismatch);
    }
}
