// Native-only: this acceptance test runs on a tokio runtime (not wasm).
#![cfg(not(target_arch = "wasm32"))]
//! Acceptance test for the FIRST consumer (Sage wallet NFT images):
//!
//! An NFT whose `data`-uri is a root-pinned DIG URN resolves to a displayable
//! image **with NO dig-node running** — the rpc.dig.net fallback. This is the exact
//! path Sage exercises via the wasm `resolveObjectUrl(urn)` (which turns the bytes
//! below into a `blob:` URL for an `<img src>`); here we assert the byte layer that
//! `resolveObjectUrl` is built on.

mod common;

use common::*;
use dig_urn_resolver::{ResolveOutcome, Resolver};

/// A minimal valid PNG (8-byte signature + a truncated IHDR) — enough for the
/// content-type sniff and to stand in as NFT image bytes.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R', // IHDR chunk header
];

#[tokio::test]
async fn sage_nft_image_resolves_over_rpc_with_no_node_running() {
    // The NFT's on-chain data-uri: a ROOT-PINNED DIG URN (as minted by #663).
    let key = "nft/image.png";
    let fx = build_fixture(key, PNG, None);
    let urn = format!("urn:dig:chia:{STORE_HEX}:{}/{}", fx.root_hex, key);

    // Node-absent: every /health + /s/ probe fails (no local dig-node); only the
    // rpc gateway answers. This is the default state on a fresh Sage install.
    let transport = MockTransport::new(
        Box::new(|_url: &str| Err(transport_err())),
        Box::new(move |_url: &str, body: &str| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            match req["method"].as_str().unwrap() {
                // Root-pinned URN → getAnchoredRoot is not needed.
                "dig.getContent" => Ok(rpc_ok(get_content_result(&fx))),
                other => panic!("root-pinned URN should only call dig.getContent, got {other}"),
            }
        }),
    );

    let outcome = Resolver::new(transport).resolve(&urn).await.unwrap();

    // Verified image bytes came back over the rpc fallback, node-absent.
    let data = match outcome {
        ResolveOutcome::Success(d) => d,
        other => panic!("expected the image to resolve over rpc, got {other:?}"),
    };
    assert_eq!(data.bytes, PNG, "the exact NFT image bytes");
    assert_eq!(data.content_type, "image/png");
    // These bytes + MIME are exactly what wasm `resolveObjectUrl` wraps in a
    // `blob:` URL for the `<img src>`.
}
