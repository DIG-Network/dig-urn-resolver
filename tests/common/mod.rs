//! Shared test scaffolding: an in-memory [`HttpTransport`] mock (no network) and a
//! real-crypto rpc fixture builder (produces byte-valid ciphertext + inclusion
//! proof via `digstore_core`, so the resolver's verify+decrypt runs the genuine
//! read-crypto path — not a stub).
//!
//! Each test binary compiles this module independently and uses a subset, so
//! per-crate "unused" is expected here.
#![allow(dead_code)]

use base64::Engine;
use dig_urn_resolver::transport::{HttpResponse, HttpTransport, TransportError};
use digstore_core::crypto::{derive_decryption_key, encrypt_chunk};
use digstore_core::{codec::Encode, resource_leaf, Bytes32, MerkleTree, SecretSalt};

type GetFn = Box<dyn Fn(&str) -> Result<HttpResponse, TransportError>>;
type PostFn = Box<dyn Fn(&str, &str) -> Result<HttpResponse, TransportError>>;

/// A programmable in-memory transport. `get`/`post_json` delegate to the supplied
/// closures, so each test scripts exactly the endpoint behaviour it needs.
pub struct MockTransport {
    get_fn: GetFn,
    post_fn: PostFn,
}

impl MockTransport {
    pub fn new(get_fn: GetFn, post_fn: PostFn) -> Self {
        MockTransport { get_fn, post_fn }
    }
}

#[async_trait::async_trait(?Send)]
impl HttpTransport for MockTransport {
    async fn get(&self, url: &str) -> Result<HttpResponse, TransportError> {
        (self.get_fn)(url)
    }
    async fn post_json(&self, url: &str, body: String) -> Result<HttpResponse, TransportError> {
        (self.post_fn)(url, &body)
    }
}

/// A plain 200 with a body and optional content-type.
pub fn ok(body: Vec<u8>, content_type: Option<&str>) -> HttpResponse {
    let headers = content_type
        .map(|c| vec![("content-type".to_string(), c.to_string())])
        .unwrap_or_default();
    HttpResponse {
        status: 200,
        headers,
        body,
    }
}

/// A bare status response with no body.
pub fn status(code: u16) -> HttpResponse {
    HttpResponse {
        status: code,
        headers: vec![],
        body: vec![],
    }
}

/// A connection-level failure.
pub fn transport_err() -> TransportError {
    TransportError("connection refused".into())
}

/// A JSON-RPC 2.0 success envelope carrying `result`.
pub fn rpc_ok(result: serde_json::Value) -> HttpResponse {
    ok(
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result })
            .to_string()
            .into_bytes(),
        Some("application/json"),
    )
}

/// A test store id (64 hex chars).
pub const STORE_HEX: &str = "abababababababababababababababababababababababababababababababab";

/// A real rpc fixture for one single-chunk resource.
pub struct RpcFixture {
    pub root_hex: String,
    pub ciphertext_b64: String,
    pub proof_b64: String,
    pub chunk_lens: Vec<u32>,
    pub total_length: u64,
}

/// Build a byte-valid rpc fixture: derive the URN key, encrypt `plaintext`, commit
/// the single ciphertext leaf into a merkle tree, and emit the base64 ciphertext +
/// inclusion proof + the root the resolver must verify against. `salt_hex` mirrors
/// a private store.
pub fn build_fixture(resource_key: &str, plaintext: &[u8], salt_hex: Option<&str>) -> RpcFixture {
    let canonical = format!("urn:dig:chia:{STORE_HEX}/{resource_key}");
    let salt = salt_hex.map(|s| SecretSalt(Bytes32::from_hex(s).unwrap().0));
    let key = derive_decryption_key(&canonical, salt.as_ref());
    let ciphertext = encrypt_chunk(&key, plaintext);

    let leaf = resource_leaf(&ciphertext);
    let tree = MerkleTree::from_leaves(vec![leaf]);
    let proof = tree.prove(0).expect("single-leaf proof");

    RpcFixture {
        root_hex: tree.root().to_hex(),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        proof_b64: base64::engine::general_purpose::STANDARD.encode(proof.to_bytes()),
        chunk_lens: vec![ciphertext.len() as u32],
        total_length: ciphertext.len() as u64,
    }
}

/// A `dig.getContent` result JSON for a complete single-window fetch.
pub fn get_content_result(fx: &RpcFixture) -> serde_json::Value {
    serde_json::json!({
        "total_length": fx.total_length,
        "offset": 0,
        "next_offset": null,
        "complete": true,
        "ciphertext": fx.ciphertext_b64,
        "inclusion_proof": fx.proof_b64,
        "chunk_lens": fx.chunk_lens,
    })
}
