//! DIG URN parsing — a thin wrapper over the canonical [`dig_urn_protocol::DigUrn`].
//!
//! Grammar (canonical; matches the SDK/extension/hub parser byte-for-byte):
//!
//! ```text
//! urn:dig:chia:<store_id>[:<root>]/<resource_key>[?salt=<hex>]
//! ```
//!
//! * `<store_id>` — 64 hex chars, the singleton launcher id (store identity).
//! * `:<root>` — OPTIONAL 64 hex chars pinning one on-chain generation. Omit for
//!   the root-independent form. The root is the trust anchor for inclusion
//!   verification only; it is NOT a key input (retrieval/decryption keys are
//!   root-independent).
//! * `<resource_key>` — the path within the store (e.g. `img/logo.png`). Empty
//!   resolves to the §8.5 default view `index.html`.
//! * `?salt=<hex>` — OPTIONAL out-of-band secret salt for a PRIVATE store.
//!
//! [`dig_urn_protocol::DigUrn`] is the single source of truth for the scheme — the same
//! parser the SDK, extension, hub, and node share — so this resolver can never skew from
//! the canonical addressing. This module adds only the resolver-facing conveniences; it
//! reimplements no parsing or key derivation.
//!
//! ## The wire key is `content_key`, never `retrieval_key`
//!
//! The ecosystem's on-wire lookup key (what the resolver sends and the node indexes as
//! `retrieval_key`) is `SHA-256(canonical_rootless())` — root-INDEPENDENT so the key is
//! stable across generations. In `dig-urn-protocol` that value is
//! [`DigUrn::content_key`](dig_urn_protocol::DigUrn::content_key). Its
//! [`retrieval_key`](dig_urn_protocol::DigUrn::retrieval_key) is a DIFFERENT, root-PINNED
//! hash. Hence [`ParsedUrn::retrieval_key_hex`] maps to `content_key_hex` — mapping it to
//! `retrieval_key_hex` would silently break every root-pinned read.

use crate::error::{ResolveError, Result};
use dig_urn_protocol::DigUrn;

/// A parsed DIG URN, retaining the pieces the resolver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrn {
    /// The canonical parsed URN (chain + store id + optional root + resource key). The
    /// salt is peeled off into [`Self::salt`], never left inside the resource key.
    pub urn: DigUrn,
    /// Private-store secret salt (lowercase hex), or `None` for a public store.
    pub salt: Option<String>,
}

impl ParsedUrn {
    /// Parse a DIG URN string, splitting off an optional `?salt=<hex>` suffix and
    /// delegating the rest to the canonical [`dig_urn_protocol::DigUrn`] parser.
    pub fn parse(input: &str) -> Result<ParsedUrn> {
        let (urn, salt) = DigUrn::parse_with_salt(input).map_err(|e| ResolveError::Parse(e.0))?;

        // An absent or empty resource path resolves to the §8.5 default view
        // `index.html` (a bare store URL / a trailing slash → the store's landing page) —
        // see [`Self::resource_key`]. It is NOT rejected here.
        Ok(ParsedUrn { urn, salt })
    }

    /// The store id as lowercase hex.
    pub fn store_id_hex(&self) -> String {
        self.urn.store_id_hex()
    }

    /// The pinned generation root as lowercase hex, if the URN carries one.
    pub fn root_hex(&self) -> Option<String> {
        self.urn.root_hex()
    }

    /// The resource path, defaulting an empty/absent key to `index.html` (§8.5).
    pub fn resource_key(&self) -> &str {
        self.urn.effective_resource_key()
    }

    /// The ecosystem wire/lookup key: `SHA-256(canonical rootless URN)`, lowercase hex.
    ///
    /// This is [`DigUrn::content_key_hex`](dig_urn_protocol::DigUrn::content_key_hex) — the
    /// root-INDEPENDENT key the node indexes. It is deliberately NOT
    /// `DigUrn::retrieval_key_hex` (the root-pinned hash); see the module docs.
    pub fn retrieval_key_hex(&self) -> String {
        self.urn.content_key_hex()
    }
}
