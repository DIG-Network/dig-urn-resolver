//! The resolver's error taxonomy.
//!
//! Two failure classes are deliberately kept apart (see the module docs on
//! [`crate::resolver`]):
//!
//! * **Hard, fail-closed errors** — [`ResolveError`] — a malformed URN, a
//!   not-found resource, or a verify/decrypt failure. A verify failure means the
//!   served bytes did not chain to the trusted on-chain root (tampered / decoy):
//!   the resolver NEVER returns those bytes, it fails closed.
//! * **The network-unreachable state** — NOT an error. When every transport tier
//!   is unreachable the resolver returns a branded HTML document via
//!   [`crate::ResolvedData`] with `unreachable == true`, so a consuming webview can
//!   render a friendly "connect a node" page instead of a crash.

use thiserror::Error;

/// A hard, fail-closed resolution failure. Distinct from the network-unreachable
/// state, which is a successful [`crate::ResolvedData`] carrying a branded page.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// The input was not a syntactically valid DIG URN.
    #[error("invalid DIG URN: {0}")]
    Parse(String),

    /// A transport-level failure talking to a specific endpoint (DNS, TLS,
    /// connection, timeout, malformed HTTP). Not the same as "every tier down"
    /// (that is the unreachable state), nor a not-found (that is [`Self::NotFound`]).
    #[error("transport error: {0}")]
    Transport(String),

    /// The RPC endpoint returned a JSON-RPC / protocol error, or a malformed
    /// response the resolver cannot interpret.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// The resource does not exist in the store at the resolved root. A hard,
    /// fail-closed verdict — never masked behind a friendly page.
    #[error("resource not found")]
    NotFound,

    /// A rootless URN was resolved over the untrusted rpc tier, where the trust root
    /// cannot be established without trusting the gateway. Pin a root in the URN
    /// (`urn:dig:chia:<store>:<root>/<path>`), or resolve via a loopback node. A
    /// hard, fail-closed error — the resolver will not verify against a
    /// gateway-asserted root.
    #[error("a root-pinned URN is required to resolve over the public gateway (rootless URNs are not chain-verified there)")]
    RootRequired,

    /// The served ciphertext failed integrity verification against the
    /// chain-anchored root (tampered bytes, a non-chaining proof, or a decoy from
    /// a wrong store). FAIL-CLOSED: the bytes are discarded, never returned.
    #[error("inclusion verification failed: {0}")]
    VerifyFailed(String),

    /// The verified ciphertext did not decrypt under the URN's key (AES-256-GCM-SIV
    /// tag failure — wrong key/salt or corruption). FAIL-CLOSED.
    #[error("decryption failed (wrong key/salt or corrupt ciphertext)")]
    DecryptFailed,
}

/// Result alias for resolver operations.
pub type Result<T> = core::result::Result<T, ResolveError>;
