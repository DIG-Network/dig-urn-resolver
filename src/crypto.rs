//! The rpc-path read-crypto — a thin orchestration over `digstore_core`.
//!
//! Every primitive here (URN key derivation, AES-256-GCM-SIV open, merkle
//! inclusion verify) is `digstore_core`'s — the SAME functions the browser
//! read-crypto (`dig-client-wasm`) and the on-chain/format crates share, so this
//! resolver can never skew from the canonical crypto. Nothing is reimplemented;
//! this module only sequences the gate-then-decrypt pipeline and maps failures to
//! the resolver's fail-closed [`ResolveError`] taxonomy.
//!
//! The node transport does NOT use this module: the node decrypts + verifies
//! server-side on the same machine and returns plaintext under a loopback trust
//! boundary. This is only for the blind rpc fetch (ciphertext + proof over the
//! public gateway), where the client MUST verify against the chain-anchored root
//! itself.

use crate::error::{ResolveError, Result};
use crate::urn::ParsedUrn;
use base64::Engine;
use digstore_core::codec::Decode;
use digstore_core::crypto::{decrypt_chunk, derive_decryption_key};
use digstore_core::{resource_leaf, Bytes32, MerkleProof, SecretSalt};

/// Parse a 32-byte secret salt from optional lowercase hex. `None`/empty ⇒ a
/// public store (the URN alone derives the key).
fn parse_salt(salt_hex: Option<&str>) -> Result<Option<[u8; 32]>> {
    match salt_hex {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => {
            let b = Bytes32::from_hex(s.trim())
                .map_err(|_| ResolveError::Parse("secret salt must be 64 hex chars".into()))?;
            Ok(Some(b.0))
        }
    }
}

/// Decode a base64 merkle proof (the `inclusion_proof` field) into a
/// [`MerkleProof`]. The wire encoding is the Chia big-endian streamable codec.
fn decode_proof_b64(proof_b64: &str) -> Result<MerkleProof> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(proof_b64.trim().as_bytes())
        .map_err(|_| ResolveError::VerifyFailed("inclusion proof is not valid base64".into()))?;
    MerkleProof::from_bytes(&raw)
        .map_err(|_| ResolveError::VerifyFailed("inclusion proof encoding is invalid".into()))
}

/// The integrity gate (Digstore §9.3): the served `ciphertext` must be the proof's
/// leaf (`leaf = SHA-256(ciphertext)`), the path must fold to `proof.root`, and
/// `proof.root` must equal the chain-anchored `trusted_root`. Any failure is a hard
/// fail-closed [`ResolveError::VerifyFailed`] — a decoy / wrong-store / tampered
/// response can never chain to the real root.
pub fn verify_inclusion(ciphertext: &[u8], proof_b64: &str, trusted_root_hex: &str) -> Result<()> {
    let trusted_root = Bytes32::from_hex(trusted_root_hex.trim())
        .map_err(|_| ResolveError::VerifyFailed("trusted root must be 64 hex chars".into()))?;
    let proof = decode_proof_b64(proof_b64)?;

    if resource_leaf(ciphertext) != proof.leaf {
        return Err(ResolveError::VerifyFailed(
            "content does not match proof leaf (tampered ciphertext)".into(),
        ));
    }
    if !proof.verify() {
        return Err(ResolveError::VerifyFailed(
            "merkle path does not resolve to the declared root".into(),
        ));
    }
    if proof.root != trusted_root {
        return Err(ResolveError::VerifyFailed(
            "merkle root does not match the chain-anchored trusted root".into(),
        ));
    }
    Ok(())
}

/// The confidentiality half: derive the URN key, split the plain-concatenated chunk
/// ciphertexts by `chunk_lens` (per-chunk CIPHERTEXT byte lengths in order — no wire
/// length framing) and AES-256-GCM-SIV-open each in order. An empty/absent
/// `chunk_lens` is the common single-chunk resource. A tag failure fails closed with
/// [`ResolveError::DecryptFailed`].
pub fn decrypt(parsed: &ParsedUrn, ciphertext: &[u8], chunk_lens: &[u32]) -> Result<Vec<u8>> {
    let salt = parse_salt(parsed.salt.as_deref())?;
    let canonical = parsed.canonical_rootless().canonical();
    let aes_key = derive_decryption_key(&canonical, salt.map(SecretSalt).as_ref());

    let plan: Vec<usize> = if chunk_lens.is_empty() {
        vec![ciphertext.len()]
    } else {
        chunk_lens.iter().map(|&l| l as usize).collect()
    };
    let total: usize = plan.iter().sum();
    if total != ciphertext.len() {
        return Err(ResolveError::Rpc(format!(
            "served ciphertext length {} does not match chunk total {total}",
            ciphertext.len(),
        )));
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut p = 0usize;
    for len in plan {
        let ct = &ciphertext[p..p + len];
        p += len;
        let pt = decrypt_chunk(&aes_key, ct).map_err(|_| ResolveError::DecryptFailed)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(plaintext)
}

/// Verify then decrypt (gate-then-decrypt): the full rpc read-crypto pipeline.
pub fn verify_and_decrypt(
    parsed: &ParsedUrn,
    ciphertext: &[u8],
    proof_b64: &str,
    trusted_root_hex: &str,
    chunk_lens: &[u32],
) -> Result<Vec<u8>> {
    verify_inclusion(ciphertext, proof_b64, trusted_root_hex)?;
    decrypt(parsed, ciphertext, chunk_lens)
}
