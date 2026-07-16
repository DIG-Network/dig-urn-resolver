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

use crate::error::{ResolveError, Result};
use crate::ladder::{self, Endpoint, EndpointKind};
use crate::pages;
use crate::transport::HttpTransport;
use crate::urn::ParsedUrn;
use crate::{node, rpc};
use std::cell::RefCell;

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
    /// a node iff its `/health` answers, else an rpc endpoint.
    pub endpoint: Option<String>,
    /// Override the "Connect to Node" CTA target on the unreachable page. Defaults
    /// to [`pages::DEFAULT_CONNECT_URL`].
    pub connect_url: Option<String>,
}

/// A URN resolver over an injected [`HttpTransport`]. The resolved ladder plan is
/// cached per instance (one `/health` probe sweep, then reused).
pub struct Resolver<T: HttpTransport + ?Sized> {
    options: ResolveOptions,
    plan_cache: RefCell<Option<Vec<Endpoint>>>,
    transport: T,
}

impl<T: HttpTransport> Resolver<T> {
    /// Build a resolver with default options.
    pub fn new(transport: T) -> Self {
        Resolver::with_options(transport, ResolveOptions::default())
    }

    /// Build a resolver with explicit options.
    pub fn with_options(transport: T, options: ResolveOptions) -> Self {
        Resolver {
            options,
            plan_cache: RefCell::new(None),
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
    async fn fetch_from(&self, endpoint: &Endpoint, parsed: &ParsedUrn) -> Result<ResolvedData> {
        match endpoint.kind {
            EndpointKind::Node => node::fetch(&self.transport, &endpoint.base, parsed).await,
            EndpointKind::Rpc => rpc::fetch(&self.transport, &endpoint.base, parsed).await,
        }
    }

    /// Resolve a DIG URN to a typed [`ResolveOutcome`].
    ///
    /// Walks the ladder plan in order. A tier's TRANSPORT failure falls through to
    /// the next tier; when the LAST tier is transport-unreachable the whole network
    /// is down → [`ResolveOutcome::Unreachable`]. A verify/decrypt failure at any
    /// tier is [`ResolveOutcome::IntegrityFailure`] IMMEDIATELY (fail-closed, never
    /// cascaded, never the friendly page). A malformed URN / not-found / rpc
    /// protocol error is a hard `Err`.
    pub async fn resolve(&self, urn: &str) -> Result<ResolveOutcome> {
        let parsed = ParsedUrn::parse(urn)?;
        let plan = self.plan().await;
        let last = plan.len().saturating_sub(1);

        for (i, endpoint) in plan.iter().enumerate() {
            match self.fetch_from(endpoint, &parsed).await {
                Ok(data) => return Ok(ResolveOutcome::Success(data)),
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
