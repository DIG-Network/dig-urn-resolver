//! The node read path — `GET {base}/s/<storeId>[:<root>]/<resourceKey>`.
//!
//! A loopback dig-node can answer in one of TWO shapes, distinguished
//! DETERMINISTICALLY by headers (never by assuming "node ⇒ plaintext"):
//!
//! 1. **Verified PLAINTEXT** — the node decrypted + verified server-side and attests
//!    `X-Dig-Verified: true`. Trusted directly (no client crypto), sound because:
//!    - **Loopback only** — this path is reached ONLY for an asserted-loopback host
//!      (the ladder's [`crate::ladder::classify`] guard); a remote/override host is
//!      routed to the client-verified rpc path instead.
//!    - **Attested** — a missing/false `X-Dig-Verified` is rejected fail-closed.
//! 2. **CIPHERTEXT** — the node relayed opaque ciphertext (marked by
//!    `X-Dig-Encrypted: true` or an `X-Dig-Inclusion-Proof` header). This is
//!    client-side VERIFIED + DECRYPTED exactly like the rpc path (merkle proof +
//!    AES-256-GCM-SIV via `digstore-core`, URN salt threaded in) — a node returning
//!    ciphertext is NOT blindly trusted.
//!
//! A response that is neither attested plaintext nor decryptable ciphertext fails
//! closed.

use crate::cache::DiskArtifacts;
use crate::content_type;
use crate::crypto;
use crate::error::{ResolveError, Result};
use crate::resolver::{Fetched, ResolvedData};
use crate::transport::HttpTransport;
use crate::urn::ParsedUrn;

/// Build the node serve URL for a parsed URN: root-pinned when the URN carries a
/// root, else the root-independent form the node resolves to its current tip.
fn serve_url(base: &str, parsed: &ParsedUrn) -> String {
    let store = match parsed.root_hex() {
        Some(root) => format!("{}:{}", parsed.store_id_hex(), root),
        None => parsed.store_id_hex(),
    };
    format!("{base}/s/{store}/{}", parsed.resource_key())
}

/// Fetch a resource from a loopback dig-node. Returns decrypted bytes + content
/// type. A `404` is a fail-closed [`ResolveError::NotFound`]; a transport failure
/// (or any other non-2xx) is [`ResolveError::Transport`] so the ladder can fall
/// through. Bytes served WITHOUT `X-Dig-Verified: true` are rejected fail-closed as
/// [`ResolveError::VerifyFailed`] — the node did not attest verification.
pub(crate) async fn fetch<T: HttpTransport + ?Sized>(
    transport: &T,
    base: &str,
    parsed: &ParsedUrn,
) -> Result<Fetched> {
    let url = serve_url(base, parsed);
    let resp = transport
        .get(&url)
        .await
        .map_err(|e| ResolveError::Transport(e.0))?;

    if resp.status == 404 {
        return Err(ResolveError::NotFound);
    }
    if !resp.is_success() {
        return Err(ResolveError::Transport(format!(
            "node returned HTTP {}",
            resp.status
        )));
    }

    // The CONCRETE root the node served, so a rootless URN can still be cached under
    // an immutable identity. Prefer the URN's pinned root, else the node's header.
    let node_root = parsed.root_hex().or_else(|| {
        resp.header("x-dig-root")
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(str::to_string)
    });

    // (1) PLAINTEXT, loopback-trusted: the node decrypted + verified server-side and
    // ATTESTED it with `X-Dig-Verified: true`. Trust it (this path is loopback-only).
    let verified_plaintext = resp
        .header("x-dig-verified")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if verified_plaintext {
        let content_type = header_content_type(&resp)
            .unwrap_or_else(|| content_type::derive(parsed.resource_key(), &resp.body));
        return Ok(Fetched {
            data: ResolvedData::new(resp.body, content_type),
            root: node_root,
            artifacts: None, // already-decrypted plaintext — not disk-re-verifiable
        });
    }

    // (2) CIPHERTEXT node path: the node relayed opaque ciphertext (blind path). We
    // MUST client-side verify+decrypt it exactly like the rpc path — reusing
    // digstore-core, threading the URN salt via `parsed`. Detected deterministically
    // by an explicit `X-Dig-Encrypted: true` marker OR the presence of the inclusion
    // proof header (never by assuming "node ⇒ plaintext").
    let is_ciphertext = resp
        .header("x-dig-encrypted")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || resp.header("x-dig-inclusion-proof").is_some();
    if is_ciphertext {
        let proof_b64 = resp
            .header("x-dig-inclusion-proof")
            .map(str::to_string)
            .ok_or_else(|| {
                ResolveError::VerifyFailed(
                    "ciphertext node response missing X-Dig-Inclusion-Proof".into(),
                )
            })?;
        // The trust root: the URN's pinned root, else the (loopback) node's X-Dig-Root.
        let root = node_root.ok_or_else(|| {
            ResolveError::VerifyFailed("ciphertext node response missing a root".into())
        })?;
        let chunk_lens = parse_chunk_lens(resp.header("x-dig-chunk-lens"))?;

        // Gate-then-decrypt against the root (salt threaded via `parsed`). Tamper /
        // wrong-or-absent salt → VerifyFailed/DecryptFailed → IntegrityFailure.
        let bytes = crypto::verify_and_decrypt(parsed, &resp.body, &proof_b64, &root, &chunk_lens)?;
        let content_type = content_type::derive(parsed.resource_key(), &bytes);
        return Ok(Fetched {
            data: ResolvedData::new(bytes, content_type),
            root: Some(root),
            // A node ciphertext response IS re-verifiable → disk-cacheable.
            artifacts: Some(DiskArtifacts {
                ciphertext: resp.body,
                proof_b64,
                chunk_lens,
            }),
        });
    }

    // (3) Neither attested plaintext nor decryptable ciphertext → fail closed.
    Err(ResolveError::VerifyFailed(
        "node response was neither X-Dig-Verified plaintext nor decryptable ciphertext".into(),
    ))
}

/// The response `Content-Type` (bare type, no params), if non-empty.
fn header_content_type(resp: &crate::transport::HttpResponse) -> Option<String> {
    resp.header("content-type")
        .map(|c| c.split(';').next().unwrap_or(c).trim().to_string())
        .filter(|c| !c.is_empty())
}

/// Parse the `X-Dig-Chunk-Lens` header (comma-separated per-chunk ciphertext byte
/// lengths). Absent/empty ⇒ a single chunk (`[]`). A malformed value fails closed.
fn parse_chunk_lens(header: Option<&str>) -> Result<Vec<u32>> {
    let Some(raw) = header.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(|n| n.trim().parse::<u32>())
        .collect::<core::result::Result<Vec<u32>, _>>()
        .map_err(|_| ResolveError::VerifyFailed("invalid X-Dig-Chunk-Lens header".into()))
}
