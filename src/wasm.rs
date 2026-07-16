//! The wasm-bindgen surface + a browser-`fetch` transport.
//!
//! Only compiled with the `wasm` feature (built by wasm-pack into
//! `@dignetwork/dig-urn-resolver`). The documented FRONT DOOR is the branded
//! [`DigNetwork`] client:
//!
//! ```js
//! import init, { DigNetwork } from "@dignetwork/dig-urn-resolver";
//! await init();
//! const dig = new DigNetwork();
//! img.src = await dig.resolveImageUrl(nftUrn);       // <img src> (Sage NFT image)
//! const { outcome, bytes, contentType } = await dig.resolve(urn);
//! ```
//!
//! - `dig.resolve(urn)` → `{ outcome, bytes: Uint8Array, contentType }`, `outcome ∈
//!   "success" | "integrity_failure" | "unreachable"`. For a non-success outcome
//!   `bytes` is the branded `text/html` page — never unverified content.
//! - `dig.resolveImageUrl(urn)` → an `<img src>` URL. Success → a `blob:` URL of the
//!   REAL verified image; ANY failure → a branded DIG error IMAGE (`data:image/svg+xml`)
//!   so the `<img>` degrades gracefully. On an integrity failure it is the STATIC
//!   branded placeholder, NEVER the unverified bytes.
//!
//! The lower-level free functions [`resolve`] / [`resolveObjectUrl`] remain
//! available, but `DigNetwork` is the SDK front door (README + example use it).
//!
//! CORS note for consuming apps (e.g. Sage/Tauri): the `/health` + `/s/` probes hit
//! `dig.local`/`localhost` from the app origin and MAY be CORS-blocked; the
//! `rpc.dig.net` fallback (`Access-Control-Allow-Origin: *`) always works, so a
//! resolve succeeds node-absent. Add the endpoints to the app's `connect-src` CSP.

use crate::error::ResolveError;
use crate::resolver::{ResolveOptions, ResolveOutcome, Resolver};
use crate::transport::{HttpResponse, HttpTransport, TransportError};
use async_trait::async_trait;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// A [`HttpTransport`] backed by the browser `fetch` (resolved off `globalThis`, so
/// it works in a window OR a worker).
#[derive(Default)]
pub struct FetchTransport;

impl FetchTransport {
    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<String>,
    ) -> Result<HttpResponse, TransportError> {
        let opts = web_sys::RequestInit::new();
        opts.set_method(method);
        opts.set_mode(web_sys::RequestMode::Cors);

        if let Some(b) = body {
            let headers = web_sys::Headers::new().map_err(js_err)?;
            headers
                .set("content-type", "application/json")
                .map_err(js_err)?;
            opts.set_headers(&headers);
            opts.set_body(&JsValue::from_str(&b));
        }

        let request = web_sys::Request::new_with_str_and_init(url, &opts).map_err(js_err)?;

        // Resolve `fetch` off the global so this works in window + worker contexts.
        let global = js_sys::global();
        let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
            .ok()
            .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
            .ok_or_else(|| TransportError("no global fetch available".into()))?;
        let promise = fetch_fn
            .call1(&global, &request)
            .map_err(js_err)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| TransportError("fetch did not return a Promise".into()))?;

        let resp_value = JsFuture::from(promise).await.map_err(js_err)?;
        let resp: web_sys::Response = resp_value
            .dyn_into()
            .map_err(|_| TransportError("fetch response was not a Response".into()))?;

        let status = resp.status();
        let mut headers = Vec::new();
        if let Ok(Some(ct)) = resp.headers().get("content-type") {
            headers.push(("content-type".to_string(), ct));
        }

        let buf = JsFuture::from(resp.array_buffer().map_err(js_err)?)
            .await
            .map_err(js_err)?;
        let body = js_sys::Uint8Array::new(&buf).to_vec();

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

fn js_err(v: JsValue) -> TransportError {
    TransportError(
        v.as_string()
            .or_else(|| js_sys::Error::from(v).message().as_string())
            .unwrap_or_else(|| "fetch failed".into()),
    )
}

#[async_trait(?Send)]
impl HttpTransport for FetchTransport {
    async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
        self.request("GET", url, None).await
    }

    async fn post_json(&self, url: &str, body: String) -> Result<HttpResponse, TransportError> {
        self.request("POST", url, Some(body)).await
    }
}

/// Map an app-supplied optional string to `Option<String>` (empty ⇒ `None`).
fn opt(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.trim().is_empty())
}

fn options(endpoint: Option<String>, connect_url: Option<String>) -> ResolveOptions {
    ResolveOptions {
        endpoint: opt(endpoint),
        connect_url: opt(connect_url),
    }
}

fn resolver(endpoint: Option<String>, connect_url: Option<String>) -> Resolver<FetchTransport> {
    Resolver::with_options(FetchTransport, options(endpoint, connect_url))
}

async fn do_resolve(
    urn: String,
    endpoint: Option<String>,
    connect_url: Option<String>,
) -> Result<ResolveOutcome, ResolveError> {
    resolver(endpoint, connect_url).resolve(&urn).await
}

/// The effective connect-CTA URL for the unreachable page (default if unset).
fn connect_or_default(connect_url: Option<String>) -> String {
    opt(connect_url).unwrap_or_else(|| crate::pages::DEFAULT_CONNECT_URL.to_string())
}

/// The typed result of [`DigNetwork::resolve`]: the outcome tag, the bytes, and —
/// on EVERY result — the MIME/content type. For a non-success outcome the bytes are
/// the branded `text/html` page (never unverified content) and `contentType` is
/// `text/html`; for a success they are the resolved resource + its type (the store's
/// stored `Content-Type` on the node path, else inferred from the URN path extension
/// / magic bytes). A consumer (e.g. the hub serving a dig-protocol resource) can set
/// the right response `Content-Type` header straight from `.contentType`.
#[wasm_bindgen]
pub struct ResolveResult {
    outcome: String,
    bytes: Vec<u8>,
    content_type: String,
}

#[wasm_bindgen]
impl ResolveResult {
    /// `"success"` | `"integrity_failure"` | `"unreachable"`.
    #[wasm_bindgen(getter)]
    pub fn outcome(&self) -> String {
        self.outcome.clone()
    }

    /// The resource bytes (or the branded page for a non-success outcome).
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// The MIME/content type — present on EVERY result.
    #[wasm_bindgen(getter, js_name = contentType)]
    pub fn content_type(&self) -> String {
        self.content_type.clone()
    }
}

/// Shape an outcome into the typed [`ResolveResult`]. For a non-success outcome the
/// bytes are the branded page (never unverified content); `contentType` is always set.
fn outcome_to_result(outcome: &ResolveOutcome, connect_url: &str) -> ResolveResult {
    let rendered = outcome.render(connect_url);
    ResolveResult {
        outcome: outcome.kind().to_string(),
        bytes: rendered.bytes,
        content_type: rendered.content_type,
    }
}

// ---------------------------------------------------------------------------
// Branded SDK front door — `DigNetwork`
// ---------------------------------------------------------------------------

/// The DIG Network resolver client — the documented, front-door JS/TS API.
///
/// ```js
/// import init, { DigNetwork } from "@dignetwork/dig-urn-resolver";
/// await init();
/// const dig = new DigNetwork();                 // or new DigNetwork(endpoint, connectUrl)
/// img.src = await dig.resolveImageUrl(nftUrn);  // <img src> — works node-absent (rpc)
/// const { outcome, bytes, contentType } = await dig.resolve(urn);
/// ```
///
/// Construct once and reuse — the ladder plan is cached per instance.
#[wasm_bindgen]
#[derive(Clone)]
pub struct DigNetwork {
    endpoint: Option<String>,
    connect_url: Option<String>,
}

#[wasm_bindgen]
impl DigNetwork {
    /// `new DigNetwork(endpoint?, connectUrl?)`.
    ///
    /// * `endpoint` — an explicit node/gateway override (§5.3): it WINS over the
    ///   auto-ladder. A loopback host may use the node path; any other host is used
    ///   as a client-verified rpc endpoint.
    /// * `connectUrl` — the "Connect to Node" target on the unreachable page.
    #[wasm_bindgen(constructor)]
    pub fn new(endpoint: Option<String>, connect_url: Option<String>) -> DigNetwork {
        DigNetwork {
            endpoint: opt(endpoint),
            connect_url: opt(connect_url),
        }
    }

    /// Resolve a DIG URN to a typed [`ResolveResult`] (`outcome`, `bytes`, and — on
    /// EVERY result — `contentType`). `outcome ∈ "success" | "integrity_failure" |
    /// "unreachable"`. For a non-success outcome `bytes` is the branded `text/html`
    /// page, never unverified content. Rejects only on a hard error (bad URN,
    /// not-found, reachable rpc protocol error, or a rootless URN over the gateway).
    pub async fn resolve(&self, urn: String) -> Result<ResolveResult, JsError> {
        let (endpoint, connect) = (self.endpoint.clone(), self.connect_url.clone());
        let outcome = do_resolve(urn, endpoint, connect.clone())
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(outcome_to_result(&outcome, &connect_or_default(connect)))
    }

    /// Resolve a DIG URN to an image URL usable directly as an `<img src>` — the
    /// Sage NFT-image path. ALWAYS returns a usable image URL, never throwing for a
    /// normal failure:
    ///
    /// * success → a `blob:` object URL of the REAL verified image (revoke it with
    ///   `URL.revokeObjectURL` when done);
    /// * any failure → a branded DIG error IMAGE as a `data:image/svg+xml` URI
    ///   (an `<img>` cannot render the HTML error docs) — integrity failure, network
    ///   unreachable, not-found, invalid URN, or a generic error.
    ///
    /// FAIL-CLOSED: on an integrity failure this is the STATIC branded placeholder
    /// image — the tampered/unverified bytes are NEVER rendered as the image.
    #[wasm_bindgen(js_name = resolveImageUrl)]
    pub async fn resolve_image_url(&self, urn: String) -> Result<String, JsError> {
        let (endpoint, connect) = (self.endpoint.clone(), self.connect_url.clone());
        match do_resolve(urn, endpoint, connect).await {
            // The real, verified image bytes as a blob URL.
            Ok(ResolveOutcome::Success(data)) => object_url(&data.bytes, &data.content_type)
                .map_err(|e| JsError::new(&e.to_string())),
            // A non-success outcome → its branded error image (never the bytes).
            Ok(other) => Ok(crate::images::data_uri(crate::images::for_outcome(&other))),
            // A hard error → the matching branded error image (never throws here).
            Err(e) => Ok(crate::images::data_uri(crate::images::for_error(&e))),
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level free functions (the branded `DigNetwork` above is the front door)
// ---------------------------------------------------------------------------

/// Low-level: resolve to a typed [`ResolveResult`]. Prefer [`DigNetwork`].
#[wasm_bindgen]
pub async fn resolve(
    urn: String,
    endpoint: Option<String>,
    connect_url: Option<String>,
) -> Result<ResolveResult, JsError> {
    DigNetwork::new(endpoint, connect_url).resolve(urn).await
}

/// Low-level: resolve to an `<img src>` URL (real blob on success, a branded error
/// image on any failure). Prefer [`DigNetwork::resolveImageUrl`].
#[wasm_bindgen(js_name = resolveObjectUrl)]
pub async fn resolve_object_url(
    urn: String,
    endpoint: Option<String>,
    connect_url: Option<String>,
) -> Result<String, JsError> {
    DigNetwork::new(endpoint, connect_url)
        .resolve_image_url(urn)
        .await
}

/// Build a `blob:` object URL from bytes + a MIME type.
fn object_url(bytes: &[u8], content_type: &str) -> Result<String, TransportError> {
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array);
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type(content_type);
    let blob =
        web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &bag).map_err(js_err)?;
    web_sys::Url::create_object_url_with_blob(&blob).map_err(js_err)
}

/// The crate version, for SRI / compatibility checks.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    crate::version().to_string()
}
