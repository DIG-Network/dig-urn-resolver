//! The §5.3 node-first connection ladder — the first reusable packaging of the
//! canonical resolution order for third-party embedding.
//!
//! Order (first that responds wins): **explicit override > `dig.local` >
//! `localhost:9778` > `rpc.dig.net`**. A node tier is chosen only when its cheap
//! `/health` probe answers; otherwise the ladder falls through to the public
//! gateway. The resolved plan is cached per [`crate::resolver::Resolver`] instance.

use crate::transport::HttpTransport;

/// The canonical DIG node port (`dig_constants::DIG_NODE_PORT`). Both local tiers
/// probe this port.
pub const DIG_NODE_PORT: u16 = 9778;

/// The installed local node's hosts-registered name (§5.3 tier 1).
pub const DIG_LOCAL_BASE: &str = "http://dig.local:9778";
/// The loopback fallback for a node not registered in hosts (§5.3 tier 2).
pub const LOCALHOST_BASE: &str = "http://localhost:9778";
/// The public gateway — the FINAL fallback only (§5.3 tier 3).
pub const RPC_DEFAULT_BASE: &str = "https://rpc.dig.net";

/// Which read surface a base URL speaks: a dig-node (`/s/` server-side decrypt) or
/// the rpc gateway (`dig.getContent` blind fetch → client verify+decrypt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// A dig-node local serve surface.
    Node,
    /// The rpc.dig.net-style JSON-RPC gateway.
    Rpc,
}

/// A resolved endpoint: a base URL and the surface it speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The base URL (no trailing slash).
    pub base: String,
    /// The read surface at `base`.
    pub kind: EndpointKind,
}

impl Endpoint {
    /// A node endpoint at `base`.
    pub fn node(base: impl Into<String>) -> Self {
        Endpoint {
            base: base.into(),
            kind: EndpointKind::Node,
        }
    }

    /// An rpc endpoint at `base`.
    pub fn rpc(base: impl Into<String>) -> Self {
        Endpoint {
            base: base.into(),
            kind: EndpointKind::Rpc,
        }
    }
}

/// Cheaply probe a node's `/health`. `true` iff it responds with a success status
/// within the transport's timeout; any transport error or non-2xx is `false`.
async fn health_ok<T: HttpTransport + ?Sized>(transport: &T, base: &str) -> bool {
    match transport.get(&format!("{base}/health")).await {
        Ok(resp) => resp.is_success(),
        Err(_) => false,
    }
}

/// Build the ordered try-plan for a resolve.
///
/// * `override_endpoint` set — the override WINS and skips the ladder: it is a node
///   iff its `/health` answers, else it is treated as an rpc endpoint. No public
///   fallback is appended (an explicit endpoint is authoritative).
/// * otherwise — probe `dig.local` then `localhost:9778`; the first healthy one
///   yields `[Node(tier), Rpc(rpc.dig.net)]` (node preferred, gateway as fallback).
///   If neither is healthy the plan is just `[Rpc(rpc.dig.net)]`.
pub async fn build_plan<T: HttpTransport + ?Sized>(
    transport: &T,
    override_endpoint: Option<&str>,
) -> Vec<Endpoint> {
    if let Some(base) = override_endpoint {
        let base = base.trim_end_matches('/').to_string();
        return if health_ok(transport, &base).await {
            vec![Endpoint::node(base)]
        } else {
            vec![Endpoint::rpc(base)]
        };
    }

    for tier in [DIG_LOCAL_BASE, LOCALHOST_BASE] {
        if health_ok(transport, tier).await {
            return vec![Endpoint::node(tier), Endpoint::rpc(RPC_DEFAULT_BASE)];
        }
    }
    vec![Endpoint::rpc(RPC_DEFAULT_BASE)]
}
