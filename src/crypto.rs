//! The rpc-path read-crypto — a thin orchestration over the canonical
//! [`dig_urn_protocol::verify`] contract, backed by `digstore_core` primitives.
//!
//! The verification LOGIC (rootless rejection, leaf-binding, path-fold, root-anchoring,
//! gate-then-decrypt, the u64-bounded chunk split) lives in `dig-urn-protocol`, over crypto
//! primitives it INJECTS via [`dig_urn_protocol::verify::ContentCrypto`]. This module supplies
//! those primitives from `digstore_core` — the SAME merkle codec + fold and AES-256-GCM-SIV
//! functions the on-chain/format crates and the browser read-crypto share — REUSED unchanged,
//! never reimplemented, so the resolver can never skew from the canonical read-crypto. It also
//! adapts the wire encodings (base64 proof, hex root, hex salt) and maps the protocol's
//! fail-closed errors into the resolver's [`ResolveError`] taxonomy.
//!
//! The node transport does NOT use this module: the node decrypts + verifies server-side on the
//! same machine and returns plaintext under a loopback trust boundary. This is only for the blind
//! rpc fetch (ciphertext + proof over the public gateway), where the client MUST verify against
//! the chain-anchored root itself.

use crate::error::{ResolveError, Result};
use crate::urn::ParsedUrn;
use base64::Engine;
use dig_urn_protocol::verify::{self, ContentCrypto, FoldedProof};
use dig_urn_protocol::{Bytes32, DigUrn, SecretSalt};
use digstore_core::codec::Decode;
use digstore_core::crypto::{decrypt_chunk, derive_decryption_key};
use digstore_core::MerkleProof;

/// The `digstore_core`-backed crypto primitives injected into the `dig-urn-protocol` verification
/// contract. Every method here delegates to a canonical `digstore_core` function unchanged.
struct DigstoreCrypto;

impl ContentCrypto for DigstoreCrypto {
    /// Decode the Chia big-endian streamable `MerkleProof` and fold its path. Returns `None`
    /// (fail-closed) on any malformed encoding or internally-inconsistent path — the path-fold
    /// rule lives in `digstore_core::MerkleProof::verify`.
    fn decode_and_fold(&self, proof: &[u8]) -> Option<FoldedProof> {
        let proof = MerkleProof::from_bytes(proof).ok()?;
        if !proof.verify() {
            return None;
        }
        Some(FoldedProof {
            leaf: Bytes32(proof.leaf.0),
            root: Bytes32(proof.root.0),
        })
    }

    /// AES-256-GCM-SIV-open ONE chunk under the key derived from the URN's rootless canonical form
    /// + optional salt. Returns `None` on an AEAD tag failure (fail-closed).
    fn decrypt_chunk(
        &self,
        urn: &DigUrn,
        salt: Option<&SecretSalt>,
        chunk: &[u8],
    ) -> Option<Vec<u8>> {
        let canonical = urn.canonical_rootless().canonical();
        let core_salt = salt.map(|s| digstore_core::SecretSalt(s.0));
        let key = derive_decryption_key(&canonical, core_salt.as_ref());
        decrypt_chunk(&key, chunk).ok()
    }
}

/// Parse the optional lowercase-hex secret salt into a [`SecretSalt`]. `None`/empty ⇒ a public
/// store (the URN alone derives the key). Reuses the canonical protocol validator (exactly 64 hex).
fn parse_salt(salt_hex: Option<&str>) -> Result<Option<SecretSalt>> {
    match salt_hex {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => DigUrn::salt_bytes(s)
            .map(Some)
            .map_err(|_| ResolveError::Parse("secret salt must be 64 hex chars".into())),
    }
}

/// Decode the hex chain-anchored trusted root into a [`Bytes32`].
fn parse_trusted_root(trusted_root_hex: &str) -> Result<Bytes32> {
    Bytes32::from_hex(trusted_root_hex.trim())
        .map_err(|_| ResolveError::VerifyFailed("trusted root must be 64 hex chars".into()))
}

/// Decode a base64 merkle proof (the `inclusion_proof` field) into its raw wire bytes.
fn decode_proof_b64(proof_b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(proof_b64.trim().as_bytes())
        .map_err(|_| ResolveError::VerifyFailed("inclusion proof is not valid base64".into()))
}

/// Map a `dig-urn-protocol` fail-closed error into the resolver's own [`ResolveError`] taxonomy.
/// The two enums are structurally identical; this keeps the resolver's public error type stable.
fn map_err(err: dig_urn_protocol::ResolveError) -> ResolveError {
    use dig_urn_protocol::ResolveError as P;
    match err {
        P::Parse(m) => ResolveError::Parse(m),
        P::Transport(m) => ResolveError::Transport(m),
        P::Rpc(m) => ResolveError::Rpc(m),
        P::NotFound => ResolveError::NotFound,
        P::RootRequired => ResolveError::RootRequired,
        P::VerifyFailed(m) => ResolveError::VerifyFailed(m),
        P::DecryptFailed => ResolveError::DecryptFailed,
    }
}

/// The integrity gate (Digstore §9.3): the served `ciphertext` must be the proof's leaf
/// (`leaf = SHA-256(ciphertext)`), the path must fold to `proof.root`, and `proof.root` must equal
/// the chain-anchored `trusted_root`. Any failure is a hard fail-closed
/// [`ResolveError::VerifyFailed`] — a decoy / wrong-store / tampered response can never chain to
/// the real root.
pub fn verify_inclusion(ciphertext: &[u8], proof_b64: &str, trusted_root_hex: &str) -> Result<()> {
    let trusted_root = parse_trusted_root(trusted_root_hex)?;
    let proof = decode_proof_b64(proof_b64)?;
    verify::verify_inclusion(&DigstoreCrypto, ciphertext, &proof, &trusted_root).map_err(map_err)
}

/// The confidentiality half: derive the URN key and AES-256-GCM-SIV-open each chunk in order,
/// splitting the plain-concatenated ciphertexts by `chunk_lens` (per-chunk CIPHERTEXT byte lengths;
/// empty ⇒ the common single-chunk resource). The untrusted `chunk_lens` is u64-bounded so a
/// crafted length can never wrap `usize` on wasm32 and slice out of bounds. A tag failure or an
/// inconsistent plan fails closed with [`ResolveError::DecryptFailed`].
pub fn decrypt(parsed: &ParsedUrn, ciphertext: &[u8], chunk_lens: &[u32]) -> Result<Vec<u8>> {
    let salt = parse_salt(parsed.salt.as_deref())?;
    verify::decrypt(
        &DigstoreCrypto,
        &parsed.urn,
        salt.as_ref(),
        ciphertext,
        chunk_lens,
    )
    .map_err(map_err)
}

/// Verify then decrypt (gate-then-decrypt): the full rpc read-crypto pipeline. Decryption is
/// reached ONLY after inclusion verification passes.
pub fn verify_and_decrypt(
    parsed: &ParsedUrn,
    ciphertext: &[u8],
    proof_b64: &str,
    trusted_root_hex: &str,
    chunk_lens: &[u32],
) -> Result<Vec<u8>> {
    let salt = parse_salt(parsed.salt.as_deref())?;
    let trusted_root = parse_trusted_root(trusted_root_hex)?;
    let proof = decode_proof_b64(proof_b64)?;
    verify::verify_and_decrypt(
        &DigstoreCrypto,
        &parsed.urn,
        salt.as_ref(),
        ciphertext,
        &proof,
        &trusted_root,
        chunk_lens,
    )
    .map_err(map_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urn() -> ParsedUrn {
        ParsedUrn::parse(&format!("urn:dig:chia:{}/a.bin", "ab".repeat(32))).unwrap()
    }

    #[test]
    fn decrypt_rejects_overflowing_chunk_lens_without_panic() {
        // `[len+2^31, 2^31]` wraps usize on wasm32; the u64-checked total must reject it cleanly
        // (fail-closed), never slice out of bounds / panic.
        let ct = vec![0u8; 10];
        let bad = [(1u32 << 31) + 10, 1u32 << 31];
        assert!(matches!(
            decrypt(&urn(), &ct, &bad),
            Err(ResolveError::DecryptFailed)
        ));
    }

    #[test]
    fn decrypt_rejects_chunk_total_mismatch() {
        let ct = vec![0u8; 10];
        assert!(matches!(
            decrypt(&urn(), &ct, &[999]),
            Err(ResolveError::DecryptFailed)
        ));
    }

    #[test]
    fn verify_inclusion_rejects_invalid_base64_proof() {
        let err = verify_inclusion(&[0u8; 4], "not base64!!", &"11".repeat(32)).unwrap_err();
        assert!(matches!(err, ResolveError::VerifyFailed(_)));
    }

    #[test]
    fn verify_inclusion_rejects_bad_trusted_root() {
        let err = verify_inclusion(&[0u8; 4], "AAAA", "not-hex").unwrap_err();
        assert!(matches!(err, ResolveError::VerifyFailed(_)));
    }
}
