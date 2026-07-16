//! The rpc read path — the blind fetch over the UNTRUSTED public gateway.
//!
//! The gateway relays opaque ciphertext + inclusion proofs; the client verifies the
//! served bytes chain to a trusted root and decrypts — the host stays BLIND. Unlike
//! the oblivious SDK (which returns raw ciphertext when a URN does not decrypt), a
//! DISPLAY resolver MUST fail closed: a verify or decrypt failure is a hard error,
//! never returned bytes.
//!
//! # The trust root MUST come from the URN, not the gateway (security invariant)
//!
//! On this untrusted tier the trusted root is taken ONLY from a root-PINNED URN
//! (`urn:…:<root>/…`). A ROOTLESS URN is REJECTED here ([`ResolveError::RootRequired`]):
//! the only source of its current root would be `dig.getAnchoredRoot` returned by the
//! SAME untrusted gateway, which for a public (unsalted) store lets a compromised
//! gateway encrypt attacker bytes under the public URN key, prove them against its
//! OWN fake root, and pass verification. Requiring a pinned root anchors trust
//! outside the gateway. (A rootless URN over the LOOPBACK node path is fine — the
//! local node is the trust anchor; the Sage NFT case pins the root regardless.)
//!
//! Wire (SYSTEM.md dig-node §): `dig.getContent {store_id, root, retrieval_key,
//! offset, length} -> {total_length, offset, next_offset?, complete?, ciphertext,
//! inclusion_proof, chunk_lens}` (base64 ciphertext + proof), paged by
//! `next_offset`/`complete`.

use crate::content_type;
use crate::crypto;
use crate::error::{ResolveError, Result};
use crate::resolver::ResolvedData;
use crate::transport::HttpTransport;
use crate::urn::ParsedUrn;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

/// The backend caps each `dig.getContent` window (Lambda/APIGW response ceiling);
/// the client loops windows until `complete`.
const RPC_WINDOW_BYTES: u64 = 3 * 1024 * 1024;

#[derive(Deserialize)]
struct GetContent {
    #[serde(default)]
    total_length: u64,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    next_offset: Option<u64>,
    #[serde(default)]
    complete: Option<bool>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    inclusion_proof: Option<String>,
    #[serde(default)]
    chunk_lens: Option<Vec<u32>>,
}

/// One JSON-RPC 2.0 call. A transport failure or non-2xx HTTP is
/// [`ResolveError::Transport`] (the endpoint is unreachable); a JSON-RPC `error`
/// object or malformed body is [`ResolveError::Rpc`] (the endpoint IS reachable —
/// a hard, reachable error, never treated as unreachable).
async fn rpc_call<T, R>(
    transport: &T,
    base: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<R>
where
    T: HttpTransport + ?Sized,
    R: for<'de> Deserialize<'de>,
{
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let resp = transport
        .post_json(base, body)
        .await
        .map_err(|e| ResolveError::Transport(e.0))?;
    if !resp.is_success() {
        return Err(ResolveError::Transport(format!(
            "rpc {method} returned HTTP {}",
            resp.status
        )));
    }
    let envelope: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| ResolveError::Rpc(format!("rpc {method}: malformed JSON ({e})")))?;
    if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("error");
        return Err(ResolveError::Rpc(format!("rpc {method}: {msg}")));
    }
    let result = envelope
        .get("result")
        .cloned()
        .ok_or_else(|| ResolveError::Rpc(format!("rpc {method}: no result")))?;
    serde_json::from_value(result)
        .map_err(|e| ResolveError::Rpc(format!("rpc {method}: unexpected result shape ({e})")))
}

/// The trust root for the untrusted rpc tier — ONLY a root-pinned URN's root.
/// A rootless URN is rejected (see the module security invariant): its root would
/// otherwise come from the same untrusted gateway, defeating verification.
fn trusted_root(parsed: &ParsedUrn) -> Result<String> {
    parsed.root_hex().ok_or(ResolveError::RootRequired)
}

/// Fetch a resource over the rpc gateway: take the pinned root, stream the windowed
/// ciphertext, then verify (fail-closed) + decrypt.
pub async fn fetch<T: HttpTransport + ?Sized>(
    transport: &T,
    base: &str,
    parsed: &ParsedUrn,
) -> Result<ResolvedData> {
    let base = base.trim_end_matches('/');
    let root = trusted_root(parsed)?;
    let retrieval_key = parsed.retrieval_key_hex();

    let mut buf: Vec<u8> = Vec::new();
    let mut total: Option<u64> = None;
    let mut proof = String::new();
    let mut chunk_lens: Vec<u32> = Vec::new();
    let mut offset: u64 = 0;

    loop {
        let r: GetContent = rpc_call(
            transport,
            base,
            "dig.getContent",
            json!({
                "store_id": parsed.store_id_hex(),
                "root": root,
                "retrieval_key": retrieval_key,
                "offset": offset,
                "length": RPC_WINDOW_BYTES,
            }),
        )
        .await?;

        if total.is_none() {
            if r.total_length == 0 {
                return Err(ResolveError::NotFound);
            }
            total = Some(r.total_length);
            buf.reserve(r.total_length as usize);
        }
        if chunk_lens.is_empty() {
            if let Some(lens) = &r.chunk_lens {
                chunk_lens = lens.clone();
            }
        }
        if let Some(ct_b64) = &r.ciphertext {
            let chunk = base64::engine::general_purpose::STANDARD
                .decode(ct_b64.trim().as_bytes())
                .map_err(|_| ResolveError::Rpc("ciphertext is not valid base64".into()))?;
            buf.extend_from_slice(&chunk);
        }
        if let Some(p) = &r.inclusion_proof {
            if !p.is_empty() {
                proof = p.clone();
            }
        }

        let _ = r.offset; // window offset echo; the client tracks its own cursor.
        match (r.complete, r.next_offset) {
            (Some(true), _) | (_, None) => break,
            (_, Some(next)) => offset = next,
        }
    }

    let bytes = crypto::verify_and_decrypt(parsed, &buf, &proof, &root, &chunk_lens)?;
    let content_type = content_type::derive(parsed.resource_key(), &bytes);
    Ok(ResolvedData::new(bytes, content_type))
}
