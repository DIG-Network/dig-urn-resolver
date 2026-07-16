//! Runnable demo of the Sage NFT-image path: `cargo run --example sage_nft_image`.
//!
//! Shows an NFT whose `data`-uri is a root-pinned DIG URN resolving to displayable
//! image bytes with NO dig-node running (the rpc.dig.net fallback). To keep the demo
//! deterministic and offline it injects an in-memory transport that plays the role
//! of "no local node + a serving rpc gateway"; against the real network you would
//! use the default `dig_urn_resolver::native::resolve(urn)` (native) or, in Sage's
//! webview, the wasm helper:
//!
//! ```js
//! import init, { resolveObjectUrl } from "@dignetwork/dig-urn-resolver";
//! await init();
//! img.src = await resolveObjectUrl(nftDataUri); // works node-absent (rpc fallback)
//! ```

use async_trait::async_trait;
use base64::Engine;
use dig_urn_resolver::transport::{HttpResponse, HttpTransport, TransportError};
use dig_urn_resolver::{ResolveOutcome, Resolver};
use digstore_core::crypto::{derive_decryption_key, encrypt_chunk};
use digstore_core::{codec::Encode, resource_leaf, MerkleTree};

const STORE_HEX: &str = "abababababababababababababababababababababababababababababababab";
const KEY: &str = "nft/image.png";
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, b'a', b'r', b't',
];

/// An in-memory transport: no local node (all GETs fail), an rpc gateway that
/// serves the fixture below.
struct DemoTransport {
    ciphertext_b64: String,
    proof_b64: String,
    total: usize,
}

#[async_trait(?Send)]
impl HttpTransport for DemoTransport {
    async fn get(&self, _url: &str) -> Result<HttpResponse, TransportError> {
        Err(TransportError(
            "no local dig-node (connection refused)".into(),
        ))
    }

    async fn post_json(&self, _url: &str, _body: String) -> Result<HttpResponse, TransportError> {
        let result = serde_json::json!({
            "total_length": self.total,
            "offset": 0,
            "next_offset": null,
            "complete": true,
            "ciphertext": self.ciphertext_b64,
            "inclusion_proof": self.proof_b64,
            "chunk_lens": [self.total],
        });
        let envelope = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result });
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: envelope.to_string().into_bytes(),
        })
    }
}

#[tokio::main]
async fn main() {
    // Build a byte-valid rpc fixture with the same read-crypto the resolver uses.
    let canonical = format!("urn:dig:chia:{STORE_HEX}/{KEY}");
    let key = derive_decryption_key(&canonical, None);
    let ciphertext = encrypt_chunk(&key, PNG);
    let tree = MerkleTree::from_leaves(vec![resource_leaf(&ciphertext)]);
    let b64 = base64::engine::general_purpose::STANDARD;

    let transport = DemoTransport {
        ciphertext_b64: b64.encode(&ciphertext),
        proof_b64: b64.encode(tree.prove(0).unwrap().to_bytes()),
        total: ciphertext.len(),
    };

    // The NFT's root-pinned data-uri.
    let urn = format!("urn:dig:chia:{STORE_HEX}:{}/{KEY}", tree.root().to_hex());
    println!("Resolving NFT image URN (no dig-node running): {urn}");

    match Resolver::new(transport).resolve(&urn).await {
        Ok(ResolveOutcome::Success(data)) => {
            println!(
                "  ✓ resolved {} bytes as {} over the rpc.dig.net fallback",
                data.bytes.len(),
                data.content_type
            );
            assert_eq!(data.bytes, PNG);
            println!("  → wasm resolveObjectUrl(urn) would wrap these bytes in a blob: URL for <img src>.");
        }
        Ok(other) => panic!("expected the image to resolve, got {other:?}"),
        Err(e) => panic!("resolve failed: {e}"),
    }
}
