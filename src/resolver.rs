//! The resolver — orchestrates URN → data over the §5.3 node-first ladder.
//!
//! # Three outcomes, deliberately kept distinct
//!
//! A resolve returns `Result<`[`ResolveOutcome`]`, `[`ResolveError`]`>`:
//!
//! * [`ResolveOutcome::Success`] — verified, decrypted content (node path:
//!   server-side decrypted under loopback trust; rpc path: client-verified against
//!   the chain-anchored root then decrypted).
//! * [`ResolveOutcome::IntegrityFailure`] — bytes WERE fetched but failed the merkle
//!   inclusion / decrypt-verify (tampered / decoy / wrong root). A hard, fail-CLOSED
//!   SECURITY outcome: the unverified bytes are discarded and NEVER returned.
//! * [`ResolveOutcome::Unreachable`] — every transport tier was down; nothing was
//!   fetched. A friendly, retryable network condition.
//!
//! `IntegrityFailure` (reached the network, bytes don't verify — security) and
//! `Unreachable` (couldn't reach the network — retryable) are never conflated.
//!
//! A malformed URN, a not-found resource, and a reachable rpc PROTOCOL error remain
//! hard [`ResolveError`]s.

use crate::cache::{self, DiskArtifacts, MemoryCache};
use crate::error::{ResolveError, Result};
use crate::ladder::{self, Endpoint, EndpointKind};
use crate::pages;
use crate::transport::HttpTransport;
use crate::urn::ParsedUrn;
use crate::{node, rpc};
// Used only by the native disk-cache re-verify path.
#[cfg(feature = "native")]
use crate::{content_type, crypto};
use std::cell::RefCell;

/// The internal result of one endpoint fetch: the resolved data plus, when known,
/// the CONCRETE content root (for the cache identity) and the verifiable artifacts
/// (rpc path only) that let the disk cache re-verify a hit.
pub(crate) struct Fetched {
    /// The verified, decrypted resource.
    pub data: ResolvedData,
    /// The concrete resolved root (pinned root on the rpc path, `X-Dig-Root` on the
    /// node path) — `None` when the tier did not expose it (then it is not cached).
    pub root: Option<String>,
    /// The verifiable rpc artifacts (ciphertext + proof + chunk lens) for the disk
    /// cache; `None` when the bytes are not re-verifiable. Consumed by the native
    /// disk cache; unused on wasm (no filesystem).
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    pub artifacts: Option<DiskArtifacts>,
}

/// The resolved bytes plus their content type. Only ever the VERIFIED content of a
/// [`ResolveOutcome::Success`], or the branded HTML of a rendered non-success
/// outcome (see [`ResolveOutcome::render`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedData {
    /// The resource bytes.
    pub bytes: Vec<u8>,
    /// The MIME type.
    pub content_type: String,
}

impl ResolvedData {
    /// Construct resolved data.
    pub fn new(bytes: Vec<u8>, content_type: String) -> Self {
        ResolvedData {
            bytes,
            content_type,
        }
    }
}

/// The typed result of a resolve. The three cases are exhaustive and never
/// conflated (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// Verified, decrypted content.
    Success(ResolvedData),
    /// The served bytes failed integrity verification — a hard, fail-closed
    /// security failure. The unverified bytes are NEVER carried here.
    IntegrityFailure,
    /// Every transport tier was unreachable — a friendly, retryable network state.
    Unreachable,
}

impl ResolveOutcome {
    /// `true` iff this is verified content.
    pub fn is_success(&self) -> bool {
        matches!(self, ResolveOutcome::Success(_))
    }

    /// The verified data, if this is a success.
    pub fn data(&self) -> Option<&ResolvedData> {
        match self {
            ResolveOutcome::Success(d) => Some(d),
            _ => None,
        }
    }

    /// A stable machine-readable tag: `"success"` / `"integrity_failure"` /
    /// `"unreachable"` (for the wasm surface + logging).
    pub fn kind(&self) -> &'static str {
        match self {
            ResolveOutcome::Success(_) => "success",
            ResolveOutcome::IntegrityFailure => "integrity_failure",
            ResolveOutcome::Unreachable => "unreachable",
        }
    }

    /// The renderable payload for a webview: the verified content for a success, or
    /// the appropriate branded `text/html` page for a non-success outcome. This is
    /// the ONLY way a non-success outcome yields bytes — an integrity failure
    /// renders the "Integrity Verification Failed" page, NEVER the unverified bytes.
    pub fn render(&self, connect_url: &str) -> ResolvedData {
        match self {
            ResolveOutcome::Success(d) => d.clone(),
            ResolveOutcome::IntegrityFailure => ResolvedData::new(
                pages::integrity_failure_html().into_bytes(),
                pages::HTML_CONTENT_TYPE.to_string(),
            ),
            ResolveOutcome::Unreachable => ResolvedData::new(
                pages::unreachable_html(connect_url).into_bytes(),
                pages::HTML_CONTENT_TYPE.to_string(),
            ),
        }
    }
}

/// Options for a resolve. All optional; defaults follow §5.3.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// An explicit endpoint override. When set it WINS and skips the ladder (§5.3):
    /// a loopback host may use the node path; any other host is a verified rpc endpoint.
    pub endpoint: Option<String>,
    /// Override the "Connect to Node" CTA target on the unreachable page. Defaults
    /// to [`pages::DEFAULT_CONNECT_URL`].
    pub connect_url: Option<String>,
    /// Optional DISK cache directory (native only). When set, verified rpc results
    /// are persisted (as re-verifiable artifacts) and re-verified on read; absent ⇒
    /// the in-memory cache only. Ignored on wasm (no filesystem).
    pub cache_path: Option<String>,
}

/// A URN resolver over an injected [`HttpTransport`]. The ladder plan and verified
/// results are cached per instance.
pub struct Resolver<T: HttpTransport + ?Sized> {
    options: ResolveOptions,
    plan_cache: RefCell<Option<Vec<Endpoint>>>,
    memory: MemoryCache,
    #[cfg(feature = "native")]
    disk: Option<cache::DiskCache>,
    transport: T,
}

impl<T: HttpTransport> Resolver<T> {
    /// Build a resolver with default options.
    pub fn new(transport: T) -> Self {
        Resolver::with_options(transport, ResolveOptions::default())
    }

    /// Build a resolver with explicit options.
    pub fn with_options(transport: T, options: ResolveOptions) -> Self {
        #[cfg(feature = "native")]
        let disk = options.cache_path.as_ref().map(cache::DiskCache::new);
        Resolver {
            plan_cache: RefCell::new(None),
            memory: MemoryCache::new(cache::DEFAULT_MEMORY_ENTRIES, cache::DEFAULT_MEMORY_BYTES),
            #[cfg(feature = "native")]
            disk,
            options,
            transport,
        }
    }
}

impl<T: HttpTransport + ?Sized> Resolver<T> {
    /// The connect-CTA URL for the unreachable page.
    pub fn connect_url(&self) -> &str {
        self.options
            .connect_url
            .as_deref()
            .unwrap_or(pages::DEFAULT_CONNECT_URL)
    }

    /// Resolve (and cache) the ordered try-plan for this instance.
    async fn plan(&self) -> Vec<Endpoint> {
        if let Some(plan) = self.plan_cache.borrow().as_ref() {
            return plan.clone();
        }
        let plan = ladder::build_plan(&self.transport, self.options.endpoint.as_deref()).await;
        *self.plan_cache.borrow_mut() = Some(plan.clone());
        plan
    }

    /// Fetch a resource from one endpoint.
    async fn fetch_from(&self, endpoint: &Endpoint, parsed: &ParsedUrn) -> Result<Fetched> {
        match endpoint.kind {
            EndpointKind::Node => node::fetch(&self.transport, &endpoint.base, parsed).await,
            EndpointKind::Rpc => rpc::fetch(&self.transport, &endpoint.base, parsed).await,
        }
    }

    /// The content-addressed cache identity for a resource at a CONCRETE root.
    fn cache_id(parsed: &ParsedUrn, root: &str) -> String {
        cache::content_id(
            &parsed.store_id_hex(),
            root,
            parsed.resource_key(),
            parsed.salt.as_deref(),
        )
    }

    /// A disk-cache hit, RE-VERIFIED against the URN's pinned root before use. `None`
    /// on miss (or a malformed entry). A tampered entry FAILS re-verification →
    /// `Some(IntegrityFailure)` and the bad file is dropped — never serves bad bytes.
    #[cfg(feature = "native")]
    fn disk_get_verified(&self, parsed: &ParsedUrn, id: &str) -> Option<ResolveOutcome> {
        let disk = self.disk.as_ref()?;
        let root = parsed.root_hex()?; // disk cache is rpc/root-pinned only
        let art = disk.get(id)?;
        match crypto::verify_and_decrypt(
            parsed,
            &art.ciphertext,
            &art.proof_b64,
            &root,
            &art.chunk_lens,
        ) {
            Ok(bytes) => {
                let ct = content_type::derive(parsed.resource_key(), &bytes);
                Some(ResolveOutcome::Success(ResolvedData::new(bytes, ct)))
            }
            // Tampered on-disk artifacts → fail closed; drop the poisoned entry.
            Err(ResolveError::VerifyFailed(_)) | Err(ResolveError::DecryptFailed) => {
                disk.remove(id);
                Some(ResolveOutcome::IntegrityFailure)
            }
            // Malformed → treat as a miss and drop it.
            Err(_) => {
                disk.remove(id);
                None
            }
        }
    }

    #[cfg(not(feature = "native"))]
    fn disk_get_verified(&self, _parsed: &ParsedUrn, _id: &str) -> Option<ResolveOutcome> {
        None
    }

    /// Cache a verified `Success` — memory always; disk when the fetch produced
    /// re-verifiable artifacts (rpc path) and a disk cache is configured.
    fn cache_success(&self, parsed: &ParsedUrn, fetched: &Fetched) {
        let Some(root) = fetched.root.as_deref() else {
            return; // no concrete root ⇒ not content-addressable ⇒ do not cache
        };
        let id = Self::cache_id(parsed, root);
        self.memory.put(id.clone(), fetched.data.clone());
        #[cfg(feature = "native")]
        if let (Some(disk), Some(art)) = (self.disk.as_ref(), fetched.artifacts.as_ref()) {
            disk.put(&id, art);
        }
        let _ = &id;
    }

    /// Resolve a DIG URN to a typed [`ResolveOutcome`].
    ///
    /// A cache layer sits IN FRONT of the network resolve but never weakens
    /// fail-closed: a memory hit is process-trusted (only holds what this process
    /// already verified); a disk hit is RE-VERIFIED against the URN's root (a
    /// tampered file → `IntegrityFailure`). Only verified `Success` bytes are cached.
    ///
    /// On a miss it walks the ladder plan: a tier's TRANSPORT failure falls through;
    /// the LAST tier transport-unreachable → [`ResolveOutcome::Unreachable`]; a
    /// verify/decrypt failure at any tier → [`ResolveOutcome::IntegrityFailure`]
    /// IMMEDIATELY (never cascaded/masked); a malformed URN / not-found / rpc
    /// protocol error → a hard `Err`.
    pub async fn resolve(&self, urn: &str) -> Result<ResolveOutcome> {
        let parsed = ParsedUrn::parse(urn)?;

        // Cache lookup ONLY when the content identity is known up-front (a pinned
        // root). A rootless URN's concrete root is only known after resolving, so it
        // is cached post-resolve (never a rootless→bytes mapping that could go stale).
        let pinned_id = parsed.root_hex().map(|root| Self::cache_id(&parsed, &root));
        if let Some(id) = &pinned_id {
            if let Some(data) = self.memory.get(id) {
                return Ok(ResolveOutcome::Success(data)); // process-trusted hit
            }
            if let Some(outcome) = self.disk_get_verified(&parsed, id) {
                if let ResolveOutcome::Success(data) = &outcome {
                    self.memory.put(id.clone(), data.clone());
                }
                return Ok(outcome);
            }
        }

        let plan = self.plan().await;
        let last = plan.len().saturating_sub(1);

        for (i, endpoint) in plan.iter().enumerate() {
            match self.fetch_from(endpoint, &parsed).await {
                Ok(fetched) => {
                    self.cache_success(&parsed, &fetched); // only verified Success is cached
                    return Ok(ResolveOutcome::Success(fetched.data));
                }
                // Reached the endpoint, bytes failed integrity → hard security
                // fail-closed. Distinct from unreachable; never cascade or mask.
                Err(ResolveError::VerifyFailed(_)) | Err(ResolveError::DecryptFailed) => {
                    return Ok(ResolveOutcome::IntegrityFailure)
                }
                // Transport-unreachable: fall through; at the last tier the whole
                // network is down → the friendly unreachable outcome.
                Err(ResolveError::Transport(_)) => {
                    if i == last {
                        return Ok(ResolveOutcome::Unreachable);
                    }
                }
                // Not-found / rpc protocol error: a hard, reachable error.
                Err(other) => return Err(other),
            }
        }

        // build_plan always yields ≥1 tier; be explicit anyway.
        Ok(ResolveOutcome::Unreachable)
    }

    /// Convenience for the webview/image path: resolve, then RENDER — verified
    /// content for a success, or the appropriate branded `text/html` page for a
    /// non-success outcome. An integrity failure renders the security page, NEVER
    /// the unverified bytes.
    pub async fn resolve_rendered(&self, urn: &str) -> Result<ResolvedData> {
        Ok(self.resolve(urn).await?.render(self.connect_url()))
    }
}
