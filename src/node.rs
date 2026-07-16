//! The node read path — `GET {base}/s/<storeId>[:<root>]/<resourceKey>`.
//!
//! A dig-node decrypts + verifies server-side on the same machine and returns
//! PLAINTEXT under a loopback trust boundary, so there is no client-side crypto
//! here: the resolver trusts the node's `X-Dig-Verified` result (the node is the
//! user's own process). This is why the node tier is preferred — it is both faster
//! and does no in-browser crypto.

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

/// Fetch a resource from a dig-node. Returns decrypted bytes + content type. A
/// `404` is a fail-closed [`ResolveError::NotFound`]; a transport failure (or any
/// other non-2xx, e.g. the node erroring mid-request) is
/// [`ResolveError::Transport`] so the ladder can fall through.
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

    // The node already knows the type; prefer its header, else derive from the path.
    let content_type = resp
        .header("content-type")
        .map(|c| c.split(';').next().unwrap_or(c).trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| content_type::derive(parsed.resource_key(), &resp.body));

    Ok(ResolvedData::new(resp.body, content_type))
}
