//! DIG URN parsing — a thin wrapper over `digstore_core::urn::Urn`.
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
//! `digstore_core::Urn::parse` owns the `urn:dig:` prefix, chain, store-id and root
//! parsing (the single source of truth). It does not understand the `?salt=` query,
//! so this module peels that suffix off first, then delegates — reusing the
//! canonicalization + retrieval-key derivation rather than reimplementing them.

use crate::error::{ResolveError, Result};
use digstore_core::{Urn, DEFAULT_RESOURCE_KEY};

/// A parsed DIG URN, retaining the pieces the resolver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrn {
    /// The canonical `digstore_core` URN (chain + store id + optional root +
    /// resource key). The salt is stripped from its `resource_key`.
    pub urn: Urn,
    /// Private-store secret salt (lowercase hex), or `None` for a public store.
    pub salt: Option<String>,
}

impl ParsedUrn {
    /// Parse a DIG URN string, splitting off an optional `?salt=<hex>` suffix and
    /// delegating the rest to the canonical `digstore_core` parser.
    pub fn parse(input: &str) -> Result<ParsedUrn> {
        let trimmed = input.trim();

        // Peel the OPTIONAL `?salt=<hex>` query off the tail before delegating.
        let (core_part, salt) = match trimmed.rsplit_once("?salt=") {
            Some((head, salt_hex)) => {
                let salt_hex = salt_hex.trim();
                if salt_hex.is_empty() || !salt_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ResolveError::Parse(
                        "?salt= must be non-empty lowercase hex".into(),
                    ));
                }
                (head, Some(salt_hex.to_ascii_lowercase()))
            }
            None => (trimmed, None),
        };

        let urn = Urn::parse(core_part).map_err(|e| ResolveError::Parse(format!("{e:?}")))?;

        // A resource path is required to resolve a specific asset; a bare store
        // URN (no `/path`) names no resource for a display resolve.
        if urn
            .resource_key
            .as_deref()
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(ResolveError::Parse(
                "URN has no resource path (expected …/<resource_key>)".into(),
            ));
        }

        Ok(ParsedUrn { urn, salt })
    }

    /// The store id as lowercase hex.
    pub fn store_id_hex(&self) -> String {
        self.urn.store_id.to_hex()
    }

    /// The pinned generation root as lowercase hex, if the URN carries one.
    pub fn root_hex(&self) -> Option<String> {
        self.urn.root_hash.map(|r| r.to_hex())
    }

    /// The resource path, defaulting an empty key to `index.html` (§8.5).
    pub fn resource_key(&self) -> &str {
        match self.urn.resource_key.as_deref() {
            Some(k) if !k.is_empty() => k,
            _ => DEFAULT_RESOURCE_KEY,
        }
    }

    /// The canonical ROOT-INDEPENDENT resource URN whose SHA-256 is the retrieval
    /// key and whose bytes seed the AES key. Dropping the root keeps the keys stable
    /// across generations (matches the host/CLI commit-time derivation).
    pub fn canonical_rootless(&self) -> Urn {
        Urn {
            chain: self.urn.chain.clone(),
            store_id: self.urn.store_id,
            root_hash: None,
            resource_key: Some(self.resource_key().to_string()),
        }
    }

    /// `retrieval_key = SHA-256(canonical rootless URN)`, lowercase hex.
    pub fn retrieval_key_hex(&self) -> String {
        self.canonical_rootless().retrieval_key().to_hex()
    }
}
