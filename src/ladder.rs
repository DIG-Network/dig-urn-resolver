//! The §5.3 node-first connection ladder — the first reusable packaging of the
//! canonical resolution order for third-party embedding.
//!
//! Order (first that responds wins): **explicit override > `dig.local` >
//! `localhost:9778` > `rpc.dig.net`**.
//!
//! # Node trust is LOOPBACK-ONLY (security invariant)
//!
//! The node `/s/` path returns bytes the *server* decrypted + verified, with NO
//! client-side crypto. That is safe ONLY because the node is the user's OWN machine
//! (a loopback trust boundary). Therefore a host is granted [`EndpointKind::Node`]
//! trust ONLY when it is an **asserted-loopback host**: a `127.0.0.0/8` / `::1`
//! literal, the reserved name `localhost`, or `dig.local` *iff it resolves to a
//! loopback address*. EVERY other host — including an explicit override pointed at a
//! remote host — MUST use the client-VERIFIED [`EndpointKind::Rpc`] path (blind
//! fetch → merkle-verify against the chain-anchored root → decrypt). This defeats
//! (a) an override aimed at an attacker host and (b) a LAN mDNS spoof of the
//! `.local` name — neither can serve unverified bytes as trusted content.

use crate::transport::HttpTransport;

/// The canonical DIG node port (`dig_constants::DIG_NODE_PORT`). Both local tiers
/// probe this port.
pub const DIG_NODE_PORT: u16 = 9778;

/// The installed local node's hosts-registered name (§5.3 tier 1). Granted node
/// trust ONLY if it resolves to loopback (see the module security invariant).
pub const DIG_LOCAL_BASE: &str = "http://dig.local:9778";
/// The loopback fallback for a node not registered in hosts (§5.3 tier 2).
pub const LOCALHOST_BASE: &str = "http://localhost:9778";
/// The public gateway — the FINAL fallback only (§5.3 tier 3).
pub const RPC_DEFAULT_BASE: &str = "https://rpc.dig.net";

/// Which read surface a base URL speaks: a dig-node (`/s/` server-side decrypt,
/// loopback-trusted) or the rpc gateway (`dig.getContent` blind fetch → client
/// verify+decrypt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// A dig-node local serve surface. ONLY ever an asserted-loopback host.
    Node,
    /// The rpc.dig.net-style JSON-RPC gateway (client-verified).
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

/// Extract the host (no scheme, path, or port) from a base URL. Handles the
/// `[ipv6]:port` bracket form and `host:port`.
pub fn host_of(base: &str) -> &str {
    let after_scheme = base.split("://").nth(1).unwrap_or(base);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    if let Some(rest) = authority.strip_prefix('[') {
        // `[ipv6]:port` → the bracketed address.
        return rest.split(']').next().unwrap_or(rest);
    }
    match authority.rfind(':') {
        Some(i) => &authority[..i],
        None => authority,
    }
}

/// Whether `host` resolves (via the OS resolver / hosts file) to loopback addresses
/// ONLY. Native performs the real lookup; on wasm (no DNS in the browser) it is
/// conservatively `false` — a non-literal name is never granted node trust there.
fn resolves_to_loopback(host: &str) -> bool {
    #[cfg(feature = "native")]
    {
        use std::net::ToSocketAddrs;
        match (host, 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<std::net::SocketAddr> = addrs.collect();
                !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback())
            }
            Err(_) => false,
        }
    }
    #[cfg(not(feature = "native"))]
    {
        let _ = host;
        false
    }
}

/// Is `host` an ASSERTED-LOOPBACK host eligible for node trust?
///
/// `true` for the reserved name `localhost`, any `127.0.0.0/8` / `::1` literal, or
/// `dig.local` when it resolves to loopback. `false` for every other host (remote
/// hosts, `rpc.dig.net`, a spoofable non-loopback `.local`).
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    let h = h.to_ascii_lowercase();
    if h == "localhost" {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    if h == "dig.local" {
        return resolves_to_loopback("dig.local");
    }
    false
}

/// Classify a base URL into a trust-correct [`Endpoint`]: node ONLY for an
/// asserted-loopback host, rpc (client-verified) for everything else.
pub fn classify(base: &str) -> Endpoint {
    let base = base.trim_end_matches('/').to_string();
    if is_loopback_host(host_of(&base)) {
        Endpoint::node(base)
    } else {
        Endpoint::rpc(base)
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
/// * `override_endpoint` set — the override WINS and skips the ladder. It is
///   [`classify`]d by HOST: a loopback host → node, ANY other host (a remote
///   override) → the client-verified rpc path. No public fallback is appended (an
///   explicit endpoint is authoritative — it never silently leaks to the gateway).
/// * otherwise — try `dig.local` then `localhost:9778`, each granted node trust ONLY
///   when it is an asserted-loopback host AND its `/health` answers; the first such
///   yields `[Node(tier), Rpc(rpc.dig.net)]`. If neither qualifies, the plan is just
///   `[Rpc(rpc.dig.net)]`.
pub async fn build_plan<T: HttpTransport + ?Sized>(
    transport: &T,
    override_endpoint: Option<&str>,
) -> Vec<Endpoint> {
    if let Some(base) = override_endpoint {
        return vec![classify(base)];
    }

    for tier in [DIG_LOCAL_BASE, LOCALHOST_BASE] {
        // Node trust requires BOTH loopback assertion AND a live /health.
        if is_loopback_host(host_of(tier)) && health_ok(transport, tier).await {
            return vec![Endpoint::node(tier), Endpoint::rpc(RPC_DEFAULT_BASE)];
        }
    }
    vec![Endpoint::rpc(RPC_DEFAULT_BASE)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parsing() {
        assert_eq!(host_of("http://dig.local:9778"), "dig.local");
        assert_eq!(host_of("http://localhost:9778"), "localhost");
        assert_eq!(host_of("http://127.0.0.1:9778"), "127.0.0.1");
        assert_eq!(host_of("http://[::1]:9778"), "::1");
        assert_eq!(host_of("https://rpc.dig.net"), "rpc.dig.net");
        assert_eq!(host_of("http://evil.example.com/path"), "evil.example.com");
    }

    #[test]
    fn loopback_hosts_only() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.5.6.7"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        // Remote + gateway hosts are NEVER loopback.
        assert!(!is_loopback_host("evil.example.com"));
        assert!(!is_loopback_host("rpc.dig.net"));
        assert!(!is_loopback_host("10.0.0.5"));
        assert!(!is_loopback_host("192.168.1.9"));
    }

    #[test]
    fn classify_grants_node_only_to_loopback() {
        assert_eq!(classify("http://127.0.0.1:9778").kind, EndpointKind::Node);
        assert_eq!(classify("http://localhost:9778").kind, EndpointKind::Node);
        assert_eq!(classify("http://[::1]:9778").kind, EndpointKind::Node);
        // A remote override + the gateway are the VERIFIED rpc path.
        assert_eq!(
            classify("http://evil.example.com:9778").kind,
            EndpointKind::Rpc
        );
        assert_eq!(classify("http://10.0.0.5:9778").kind, EndpointKind::Rpc);
        assert_eq!(classify("https://rpc.dig.net").kind, EndpointKind::Rpc);
    }
}
