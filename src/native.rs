//! The native runtime surface: a `reqwest` HTTP transport plus convenience entry
//! points (`resolve`, `resolve_with`, `resolve_blocking`) that wire it up.
//!
//! Only compiled with the `native` feature (the default). A short connect timeout
//! makes the `/health` ladder probes fall through fast when no local node is up.

use crate::error::Result;
use crate::resolver::{ResolveOptions, ResolveOutcome, Resolver};
use crate::transport::{HttpResponse, HttpTransport, TransportError};
use async_trait::async_trait;
use std::time::Duration;

/// A [`HttpTransport`] backed by `reqwest`. Cheap to clone/reuse.
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with sensible timeouts (fast connect so dead ladder tiers
    /// fall through quickly; a generous overall budget for large assets).
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client builds with default TLS");
        ReqwestTransport { client }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

// Local alias so the impls read cleanly without leaking into the public API.
type Result0<T> = core::result::Result<T, TransportError>;

/// Collect a `reqwest` response into the transport-agnostic [`HttpResponse`].
async fn collect(resp: reqwest::Response) -> Result0<HttpResponse> {
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp
        .bytes()
        .await
        .map_err(|e| TransportError(e.to_string()))?
        .to_vec();
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[async_trait(?Send)]
impl HttpTransport for ReqwestTransport {
    async fn get(&self, url: &str) -> Result0<HttpResponse> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        collect(resp).await
    }

    async fn post_json(&self, url: &str, body: String) -> Result0<HttpResponse> {
        let resp = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        collect(resp).await
    }
}

/// Resolve a DIG URN with the default `reqwest` transport and default options.
pub async fn resolve(urn: &str) -> Result<ResolveOutcome> {
    resolve_with(urn, ResolveOptions::default()).await
}

/// Resolve a DIG URN with the default `reqwest` transport and explicit options.
pub async fn resolve_with(urn: &str, options: ResolveOptions) -> Result<ResolveOutcome> {
    Resolver::with_options(ReqwestTransport::new(), options)
        .resolve(urn)
        .await
}

/// Blocking convenience: resolve on a private current-thread tokio runtime. For
/// callers outside an async context (a CLI, a sync FFI boundary).
pub fn resolve_blocking(urn: &str) -> Result<ResolveOutcome> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread tokio runtime builds");
    rt.block_on(resolve(urn))
}
