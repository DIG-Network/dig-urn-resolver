//! The wasm-bindgen surface + a browser-`fetch` transport.
//!
//! Only compiled with the `wasm` feature (built by wasm-pack into
//! `@dignetwork/dig-urn-resolver`). Exposes two async entry points:
//!
//! * [`resolve`] — `Promise<{ outcome, bytes: Uint8Array, contentType: string }>`
//!   where `outcome` is `"success"` / `"integrity_failure"` / `"unreachable"`. For a
//!   non-success outcome `bytes` is the branded `text/html` page (never the
//!   unverified content), so the app can render it or key off `outcome`.
//! * [`resolveObjectUrl`] — `Promise<string>`: a `blob:` object URL usable directly
//!   as an `<img src>` — the Sage NFT-image case. On an integrity failure this is
//!   the security page, NEVER the unverified bytes.
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

/// Resolve a DIG URN to a typed outcome.
///
/// Resolves to `{ outcome, bytes: Uint8Array, contentType: string }` where `outcome`
/// is one of `"success"`, `"integrity_failure"`, or `"unreachable"`:
///
/// * `"success"` — `bytes` is the VERIFIED content, `contentType` its MIME type.
/// * `"integrity_failure"` — the served bytes failed verification (tampered/decoy).
///   A SECURITY failure: `bytes` is the branded "Integrity Verification Failed"
///   `text/html` page, NEVER the unverified content.
/// * `"unreachable"` — every tier was down: `bytes` is the branded "DIG Network
///   unreachable" `text/html` page.
///
/// Rejects (throws) only on a hard error: a malformed URN, a not-found resource, or
/// a reachable rpc protocol error.
#[wasm_bindgen]
pub async fn resolve(
    urn: String,
    endpoint: Option<String>,
    connect_url: Option<String>,
) -> Result<JsValue, JsError> {
    let connect = connect_url.clone();
    let outcome = do_resolve(urn, endpoint, connect_url)
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

    let connect_url = opt(connect).unwrap_or_else(|| crate::pages::DEFAULT_CONNECT_URL.to_string());
    let rendered = outcome.render(&connect_url);

    let obj = js_sys::Object::new();
    set(&obj, "outcome", &JsValue::from_str(outcome.kind()));
    set(
        &obj,
        "bytes",
        &js_sys::Uint8Array::from(rendered.bytes.as_slice()),
    );
    set(
        &obj,
        "contentType",
        &JsValue::from_str(&rendered.content_type),
    );
    Ok(obj.into())
}

/// Resolve a DIG URN to a `blob:` object URL usable directly as an `<img src>` —
/// the Sage NFT-image helper.
///
/// On `"success"` the URL is the VERIFIED content. On `"integrity_failure"` the URL
/// is the branded "Integrity Verification Failed" `text/html` page — the unverified
/// bytes are NEVER returned as an image. On `"unreachable"` it is the branded
/// unreachable page. Pair with [`resolve`] when the app must distinguish the cases
/// programmatically. Revoke the URL (`URL.revokeObjectURL`) when done.
#[wasm_bindgen(js_name = resolveObjectUrl)]
pub async fn resolve_object_url(
    urn: String,
    endpoint: Option<String>,
    connect_url: Option<String>,
) -> Result<String, JsError> {
    let connect = connect_url.clone();
    let outcome = do_resolve(urn, endpoint, connect_url)
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;
    let connect_url = opt(connect).unwrap_or_else(|| crate::pages::DEFAULT_CONNECT_URL.to_string());
    // `render` is the ONLY byte source: an integrity failure yields the security
    // page, never the unverified content.
    let rendered = outcome.render(&connect_url);
    object_url(&rendered.bytes, &rendered.content_type).map_err(|e| JsError::new(&e.to_string()))
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

fn set(obj: &js_sys::Object, key: &str, value: &JsValue) {
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
}

/// The crate version, for SRI / compatibility checks.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    crate::version().to_string()
}
