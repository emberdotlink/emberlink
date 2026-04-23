// Grant chains use the Ed25519 signing format exposed by `SignedBlock`.
// Each block is verified with the preceding block's `pubkey_next`, preserving
// the chain attenuation invariant without another token encoding.

use core_types::{Block, CanonicalEncode, SignedBlock};
use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier,
    VerifyingKey,
};
use getrandom::fill as os_fill;
use zeroize::Zeroize;

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
    /// A block carries the pre-earlier releases `"unsigned-phase1"` placeholder in
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
                write!(f, "block 0 signature does not verify against the declared root public key")
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

/// Literal placeholder string emitted by pre-earlier releases code paths that could
/// not yet access persona root keys (`ember-daemon/src/grant.rs`). Exposed
/// so callers can detect pre-migration grants explicitly.
pub const UNSIGNED_PHASE1_PLACEHOLDER: &str = "unsigned-phase1";

/// Returns true if `sb` carries the pre-earlier releases placeholder in either the
/// signature or `pubkey_next` field. Used by `verify_chain` to reject
/// pre-migration grants up front with a structured error rather than
/// returning `SignatureMismatch` (which would be a lie — nothing was
/// signed at all).
fn is_unsigned_phase1(sb: &SignedBlock) -> bool {
    sb.signature == UNSIGNED_PHASE1_PLACEHOLDER
        || sb.pubkey_next == UNSIGNED_PHASE1_PLACEHOLDER
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
/// other signing keys). This type derives `Zeroize` so the in-memory copy
/// is wiped on drop.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct PubkeyNextKeyPair {
    pub public_hex: String,
    pub secret_hex: String,
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
        Self { public_hex, secret_hex }
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
        Ok(Self { public_hex, secret_hex })
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
#[derive(Debug, Clone)]
pub struct RootKeyPair {
    pub public_hex: String,
    pub secret_hex: String,
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
        Ok(Self { public_hex, secret_hex })
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
/// Generates a fresh `pubkey_next` keypair and signs the block's
/// `CanonicalEncode`d bytes with the root private key. Returns both the
/// resulting `SignedBlock` and the `pubkey_next` secret — the caller must
/// persist the secret to later append block 1.
pub fn sign_block_zero(
    root_key: &RootKeyPair,
    block: &Block,
) -> Result<SignedBlockOutput, ChainError> {
    let root_signing = root_key.signing_key()?;
    let pubkey_next = PubkeyNextKeyPair::generate();
    let payload = block.canonical_encode();
    let signature = root_signing.sign(&payload);
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
/// The caller is responsible for pairing the right `prev_pubkey_next`
/// secret with the right predecessor block. This function does not
/// re-verify the whole chain — use `verify_chain` for that.
pub fn sign_appended_block(
    prev_pubkey_next: &PubkeyNextKeyPair,
    block: &Block,
) -> Result<SignedBlockOutput, ChainError> {
    let prev_signing = prev_pubkey_next.signing_key()?;
    let pubkey_next = PubkeyNextKeyPair::generate();
    let payload = block.canonical_encode();
    let signature = prev_signing.sign(&payload);
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
///   declared root Ed25519 public key, 32 raw bytes).
/// - Each subsequent block is verified against the previous `SignedBlock`'s
///   `pubkey_next`.
///
/// Canonical-encodes each block with `CanonicalEncode` — any tampering of
/// block payload or reorder of blocks breaks the chain.
pub fn verify_chain(blocks: &[SignedBlock], root_pubkey: &[u8]) -> Result<(), ChainError> {
    if blocks.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    // Reject pre-earlier releases placeholders explicitly. These strings are not
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

    let root_verifying = VerifyingKey::from_bytes(
        root_pubkey
            .try_into()
            .map_err(|_| ChainError::InvalidEncoding("root pubkey must be 32 bytes".into()))?,
    )
    .map_err(|err| ChainError::InvalidEncoding(format!("invalid root pubkey: {err}")))?;

    // Block 0 — signed by root.
    verify_one(&blocks[0], &root_verifying, 0).map_err(|err| {
        // Remap generic signature-mismatch at block 0 to a more precise
        // root-key-mismatch error so callers can distinguish "chain forged
        // against a different persona" from "chain internally inconsistent."
        if matches!(err, ChainError::SignatureMismatch { block_index: 0 }) {
            ChainError::RootKeyMismatch
        } else {
            err
        }
    })?;

    // Blocks 1..N — each signed by the previous block's pubkey_next.
    for i in 1..blocks.len() {
        let prev_pubkey_hex = &blocks[i - 1].pubkey_next;
        let prev_pubkey_bytes = decode_pubkey(prev_pubkey_hex)?;
        let prev_verifying = VerifyingKey::from_bytes(&prev_pubkey_bytes).map_err(|err| {
            ChainError::InvalidEncoding(format!(
                "invalid pubkey_next at block {}: {err}",
                i - 1
            ))
        })?;
        verify_one(&blocks[i], &prev_verifying, i)?;
    }
    Ok(())
}

fn verify_one(
    sb: &SignedBlock,
    signer_pubkey: &VerifyingKey,
    block_index: usize,
) -> Result<(), ChainError> {
    let sig_bytes = hex::decode(&sb.signature)
        .map_err(|err| ChainError::InvalidEncoding(format!("invalid signature hex: {err}")))?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding("signature must be 64 bytes".into()))?;
    let signature = DalekSignature::from_bytes(&sig_array);

    // Also validate pubkey_next is well-formed here so a chain that was
    // partially corrupted at a tail block fails cleanly.
    let _ = decode_pubkey(&sb.pubkey_next)?;

    let payload = sb.block.canonical_encode();
    signer_pubkey
        .verify(&payload, &signature)
        .map_err(|_| ChainError::SignatureMismatch { block_index })
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
    if key_pair.algorithm != core_types::KeyAlgorithm::Ed25519 {
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
    use core_types::{ResourceSelector, ResourceType, Statement, Usage};

    fn fresh_root_keypair() -> (RootKeyPair, [u8; 32]) {
        let mut seed = [0u8; 32];
        os_fill(&mut seed).unwrap();
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
                resource: ResourceSelector::Exact { value: "obj-github-token".into() },
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
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

        let chain = vec![out0.signed.clone(), out1.signed.clone(), out2.signed.clone()];
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
        let (root_a, _root_a_pubkey) = fresh_root_keypair();
        let (_root_b, root_b_pubkey) = fresh_root_keypair();
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
        let local = crate::generate_local_key_pair("root", "root-a");
        let root_kp = root_key_from_local_key_pair(&local).unwrap();
        let block = sample_block("Stmt0", 42);
        let out = sign_block_zero(&root_kp, &block).unwrap();

        let root_pubkey_bytes = hex::decode(&root_kp.public_hex).unwrap();
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
}
