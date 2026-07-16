//! The injected HTTP transport — the one seam between the resolver's protocol
//! logic and the runtime's networking.
//!
//! The resolver never calls `reqwest` or the browser `fetch` directly; it depends
//! only on [`HttpTransport`], so the SAME orchestration is exercised natively (the
//! `reqwest` impl behind the `native` feature), in the browser (the `fetch` impl
//! behind the `wasm` feature), and under test (an in-memory mock — no network).

use async_trait::async_trait;

/// A minimal HTTP response the resolver cares about: status, headers, and body.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// Response headers, lowercased names.
    pub headers: Vec<(String, String)>,
    /// The raw response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A `2xx` status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Look up a response header (case-insensitive), returning its value.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.as_str())
    }
}

/// A transport-level failure (DNS, TLS, connect, timeout, malformed HTTP). The
/// ladder treats any transport error on a tier as "unreachable" and falls through.
#[derive(Debug, Clone)]
pub struct TransportError(pub String);

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TransportError {}

/// The async HTTP surface the resolver needs: a GET (content + health probes) and
/// a JSON POST (the JSON-RPC calls).
///
/// `?Send` — browser futures are not `Send`; native `reqwest` futures satisfy the
/// relaxed bound anyway, so one trait serves both runtimes.
#[async_trait(?Send)]
pub trait HttpTransport {
    /// GET `url`. A network/timeout failure is a [`TransportError`]; an HTTP error
    /// status (404, 5xx) is a successful [`HttpResponse`] the caller interprets.
    async fn get(&self, url: &str) -> Result<HttpResponse, TransportError>;

    /// POST a JSON body to `url` with `content-type: application/json`.
    async fn post_json(&self, url: &str, body: String) -> Result<HttpResponse, TransportError>;
}
