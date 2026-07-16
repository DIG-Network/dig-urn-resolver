//! The node read path — `GET {base}/s/<storeId>[:<root>]/<resourceKey>`.
//!
//! A dig-node decrypts + verifies server-side on the same machine and returns
//! PLAINTEXT under a loopback trust boundary, so there is no client-side crypto
//! here. Two conditions make that trust sound, and BOTH are enforced:
//!
//! 1. **Loopback only** — this path is reached ONLY for an asserted-loopback host
//!    (the ladder's [`crate::ladder::classify`] guard); a remote/override host is
//!    routed to the client-verified rpc path instead.
//! 2. **The node asserted it verified** — the response MUST carry
//!    `X-Dig-Verified: true`. A missing/false header means the node did NOT verify
//!    the bytes against the chain-anchored root, so they are rejected fail-closed
//!    (never returned as content).

use crate::content_type;
use crate::error::{ResolveError, Result};
use crate::resolver::ResolvedData;
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
pub async fn fetch<T: HttpTransport + ?Sized>(
    transport: &T,
    base: &str,
    parsed: &ParsedUrn,
) -> Result<ResolvedData> {
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

    // Require the node's verification attestation. Absent/false ⇒ the node did not
    // verify the bytes against the chain-anchored root → fail closed.
    let verified = resp
        .header("x-dig-verified")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !verified {
        return Err(ResolveError::VerifyFailed(
            "node did not assert X-Dig-Verified: true".into(),
        ));
    }

    // The node already knows the type; prefer its header, else derive from the path.
    let content_type = resp
        .header("content-type")
        .map(|c| c.split(';').next().unwrap_or(c).trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| content_type::derive(parsed.resource_key(), &resp.body));

    Ok(ResolvedData::new(resp.body, content_type))
}
