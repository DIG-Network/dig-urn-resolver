//! # dig-urn-resolver
//!
//! Resolve a DIG URN to its data through the protocol, node-first.
//!
//! Given a `urn:dig:chia:<store_id>[:<root>]/<resource_key>[?salt=<hex>]`, this
//! crate returns the resource's bytes + content type, following the canonical §5.3
//! ladder — **explicit override > `dig.local` > `localhost:9778` > `rpc.dig.net`** —
//! and using the first tier that responds:
//!
//! * **node tier** (`GET /s/<storeId>[:<root>]/<path>`) — a local dig-node decrypts
//!   + verifies server-side under a loopback trust boundary and returns plaintext.
//! * **rpc tier** (`dig.getContent`) — a blind fetch of opaque ciphertext +
//!   inclusion proofs from the untrusted public gateway, VERIFIED against the
//!   URN's PINNED root and decrypted client-side (fail-closed). The trust root is
//!   NEVER taken from the gateway; a rootless URN is rejected on this tier.
//!
//! ## Reuse, not reimplementation
//! All read-crypto (URN canonicalization + retrieval-key derivation, merkle
//! inclusion verify, AES-256-GCM-SIV open) is `digstore_core`'s — the same
//! functions the browser read-crypto and the on-chain crates share — so this crate
//! can never skew from the canonical crypto. It adds only the ladder, the injected
//! transport, content-type derivation, fail-closed assembly, and the wasm glue.
//!
//! ## Outcomes
//! A resolve returns `Result<`[`ResolveOutcome`]`, `[`ResolveError`]`>` — three
//! distinct outcomes, never conflated:
//! * [`ResolveOutcome::Success`] — verified, decrypted content.
//! * [`ResolveOutcome::IntegrityFailure`] — bytes were fetched but failed merkle/
//!   decrypt verification (tampered / decoy / wrong root). A hard, fail-CLOSED
//!   SECURITY outcome — the unverified bytes are NEVER returned. `resolveObjectUrl`
//!   renders a branded "Integrity Verification Failed" page, never the bytes.
//! * [`ResolveOutcome::Unreachable`] — every tier was down; nothing fetched. A
//!   friendly, retryable "connect a node" page.
//!
//! A malformed URN, a not-found resource, and a reachable rpc protocol error are
//! hard [`ResolveError`]s.
//!
//! ## First consumer
//! Sage wallet NFT images: an NFT `data`-uri that is a root-pinned DIG URN →
//! `resolveObjectUrl(urn)` (wasm) → an object URL usable as an `<img src>`, working
//! with no dig-node running (rpc fallback) and faster when a node is present.

pub mod cache;
pub mod content_type;
pub mod crypto;
pub mod error;
pub mod images;
pub mod ladder;
pub mod node;
pub mod pages;
pub mod resolver;
pub mod rpc;
pub mod transport;
pub mod urn;

pub use error::{ResolveError, Result};
pub use ladder::{
    Endpoint, EndpointKind, DIG_LOCAL_BASE, DIG_NODE_PORT, LOCALHOST_BASE, RPC_DEFAULT_BASE,
};
pub use pages::DEFAULT_CONNECT_URL;
pub use resolver::{ResolveOptions, ResolveOutcome, ResolvedData, Resolver};
pub use transport::{HttpResponse, HttpTransport, TransportError};
pub use urn::ParsedUrn;

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "wasm")]
pub mod wasm;

/// The crate version (matches `Cargo.toml`), for compatibility checks.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
