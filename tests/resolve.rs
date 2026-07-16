//! End-to-end resolver behaviour over the in-memory mock transport (no network),
//! exercising the genuine `digstore_core` read-crypto via real fixtures.
//!
//! Covers: URN parse; the §5.3 ladder (node-when-healthy, rpc-else, override wins);
//! the node + rpc transports; the three distinct outcomes — `Success`,
//! `IntegrityFailure` (fail-CLOSED on tampered/verify/decrypt failure, never the
//! bytes), and `Unreachable` (both tiers down, friendly page) — and the render/
//! object-url invariant that unverified bytes are never surfaced.

mod common;

use common::*;
use dig_urn_resolver::{ResolveError, ResolveOptions, ResolveOutcome, ResolvedData, Resolver};

const IMG_KEY: &str = "img/logo.png";

fn rootless_urn(key: &str) -> String {
    format!("urn:dig:chia:{STORE_HEX}/{key}")
}

fn root_pinned_urn(key: &str, root_hex: &str) -> String {
    format!("urn:dig:chia:{STORE_HEX}:{root_hex}/{key}")
}

/// Unwrap a `Success`, failing loudly on any other outcome.
fn success(outcome: ResolveOutcome) -> ResolvedData {
    match outcome {
        ResolveOutcome::Success(d) => d,
        other => panic!("expected Success, got {other:?}"),
    }
}

/// A mock whose node tier is healthy and serves the resource plaintext directly.
fn node_serving(plaintext: Vec<u8>, content_type: &'static str) -> MockTransport {
    let pt = plaintext.clone();
    MockTransport::new(
        Box::new(move |url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else if url.contains("/s/") {
                Ok(ok(pt.clone(), Some(content_type)))
            } else {
                Err(transport_err())
            }
        }),
        Box::new(|_url, _body| Err(transport_err())),
    )
}

/// A mock with NO node (health probes fail) but a serving rpc gateway.
fn rpc_serving(fx: RpcFixture) -> MockTransport {
    MockTransport::new(
        Box::new(|_url: &str| Err(transport_err())), // no node: every probe/GET fails
        Box::new(move |_url: &str, body: &str| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            match req["method"].as_str().unwrap() {
                "dig.getAnchoredRoot" => Ok(rpc_ok(serde_json::json!({ "root": fx.root_hex }))),
                "dig.getContent" => Ok(rpc_ok(get_content_result(&fx))),
                other => panic!("unexpected rpc method {other}"),
            }
        }),
    )
}

// --- URN parsing -----------------------------------------------------------

#[tokio::test]
async fn rejects_non_urn() {
    let t = node_serving(vec![], "text/plain");
    let err = Resolver::new(t).resolve("not-a-urn").await.unwrap_err();
    assert!(matches!(err, ResolveError::Parse(_)));
}

#[tokio::test]
async fn rejects_urn_without_resource_path() {
    let t = node_serving(vec![], "text/plain");
    let err = Resolver::new(t)
        .resolve(&format!("urn:dig:chia:{STORE_HEX}"))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Parse(_)));
}

// --- ladder: node preferred when healthy -----------------------------------

#[tokio::test]
async fn node_tier_serves_when_healthy() {
    let t = node_serving(b"hello world".to_vec(), "text/plain");
    let data = success(
        Resolver::new(t)
            .resolve(&rootless_urn("index.html"))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"hello world");
    assert_eq!(data.content_type, "text/plain");
}

#[tokio::test]
async fn node_content_type_falls_back_to_extension_when_header_absent() {
    // Node serves bytes but omits content-type → derived from the .png path.
    let t = MockTransport::new(
        Box::new(|url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(ok(vec![1, 2, 3], None))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let data = success(
        Resolver::new(t)
            .resolve(&rootless_urn(IMG_KEY))
            .await
            .unwrap(),
    );
    assert_eq!(data.content_type, "image/png");
}

#[tokio::test]
async fn node_404_is_fail_closed_not_found() {
    let t = MockTransport::new(
        Box::new(|url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(status(404))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let err = Resolver::new(t)
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::NotFound));
}

// --- ladder: rpc fallback when no node -------------------------------------

#[tokio::test]
async fn rpc_tier_resolves_rootless_via_anchored_root() {
    let fx = build_fixture(IMG_KEY, b"\x89PNG payload", None);
    let data = success(
        Resolver::new(rpc_serving(fx))
            .resolve(&rootless_urn(IMG_KEY))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"\x89PNG payload");
    assert_eq!(data.content_type, "image/png");
}

#[tokio::test]
async fn rpc_tier_resolves_root_pinned_without_anchored_root_call() {
    let fx = build_fixture(IMG_KEY, b"pinned bytes", None);
    let root = fx.root_hex.clone();
    // getAnchoredRoot must NOT be called for a root-pinned URN.
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(move |_u: &str, body: &str| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            match req["method"].as_str().unwrap() {
                "dig.getContent" => Ok(rpc_ok(get_content_result(&fx))),
                other => panic!("root-pinned URN must not call {other}"),
            }
        }),
    );
    let data = success(
        Resolver::new(t)
            .resolve(&root_pinned_urn(IMG_KEY, &root))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"pinned bytes");
}

#[tokio::test]
async fn rpc_private_store_salt_decrypts() {
    let salt = "cd".repeat(32);
    let fx = build_fixture(IMG_KEY, b"secret art", Some(&salt));
    let data = success(
        Resolver::new(rpc_serving(fx))
            .resolve(&format!("{}?salt={}", rootless_urn(IMG_KEY), salt))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"secret art");
}

#[tokio::test]
async fn rpc_not_found_when_no_anchored_root() {
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|_u: &str, _b: &str| Ok(rpc_ok(serde_json::json!({ "root": null })))),
    );
    let err = Resolver::new(t)
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::NotFound));
}

// --- IntegrityFailure: fail-CLOSED, distinct, never the bytes --------------

#[tokio::test]
async fn tampered_ciphertext_is_integrity_failure_not_data() {
    let mut tampered = build_fixture(IMG_KEY, b"authentic", None);
    // Valid proof + root, but different ciphertext whose leaf won't match.
    tampered.ciphertext_b64 = base64_of(b"tampered ciphertext bytes!!");
    tampered.total_length = 27;
    tampered.chunk_lens = vec![27];
    let outcome = Resolver::new(rpc_serving(tampered))
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::IntegrityFailure);
    assert!(
        outcome.data().is_none(),
        "must never carry the unverified bytes"
    );
}

#[tokio::test]
async fn wrong_salt_is_integrity_failure() {
    // Ciphertext committed WITHOUT salt, resolved WITH one → inclusion verifies
    // (authentic bytes) but the decrypt tag fails → integrity failure.
    let fx = build_fixture(IMG_KEY, b"art", None);
    let wrong_salt = "ef".repeat(32);
    let outcome = Resolver::new(rpc_serving(fx))
        .resolve(&format!("{}?salt={}", rootless_urn(IMG_KEY), wrong_salt))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::IntegrityFailure);
}

#[tokio::test]
async fn integrity_failure_renders_security_page_never_the_bytes() {
    let mut tampered = build_fixture(IMG_KEY, b"authentic", None);
    tampered.ciphertext_b64 = base64_of(b"evil");
    tampered.total_length = 4;
    tampered.chunk_lens = vec![4];
    let rendered = Resolver::new(rpc_serving(tampered))
        .resolve_rendered(&rootless_urn(IMG_KEY))
        .await
        .unwrap();
    assert_eq!(rendered.content_type, "text/html");
    let html = String::from_utf8(rendered.bytes).unwrap();
    assert!(html.contains("Integrity Verification Failed"));
    assert!(
        !html.contains("evil"),
        "unverified bytes must never be rendered"
    );
    // The security page is NOT dressed up as the retryable network page.
    assert!(!html.contains("Connect to Node"));
}

#[tokio::test]
async fn rpc_protocol_error_is_hard_error_not_unreachable() {
    // Endpoint IS reachable (200) but returns a JSON-RPC error → hard Rpc error,
    // never the friendly unreachable page nor an integrity failure.
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|_u: &str, _b: &str| {
            Ok(ok(
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "boom" } })
                    .to_string()
                    .into_bytes(),
                Some("application/json"),
            ))
        }),
    );
    let err = Resolver::new(t)
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::Rpc(_)));
}

// --- Unreachable → friendly branded HTML (distinct from integrity failure) --

#[tokio::test]
async fn both_tiers_unreachable_is_unreachable_outcome() {
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|_u: &str, _b: &str| Err(transport_err())),
    );
    let outcome = Resolver::new(t)
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::Unreachable);

    let rendered = outcome.render("https://dig.net");
    assert_eq!(rendered.content_type, "text/html");
    let html = String::from_utf8(rendered.bytes).unwrap();
    assert!(html.contains("DIG Network unreachable"));
    assert!(html.contains("Connect to Node"));
    assert!(html.contains("https://dig.net"));
    // Unmistakably NOT the security page.
    assert!(!html.contains("Integrity Verification Failed"));
}

#[tokio::test]
async fn unreachable_connect_url_is_overridable() {
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|_u: &str, _b: &str| Err(transport_err())),
    );
    let opts = ResolveOptions {
        connect_url: Some("dig://home".into()),
        ..Default::default()
    };
    let rendered = Resolver::with_options(t, opts)
        .resolve_rendered(&rootless_urn(IMG_KEY))
        .await
        .unwrap();
    let html = String::from_utf8(rendered.bytes).unwrap();
    assert!(html.contains("dig://home"));
}

// --- explicit override wins ------------------------------------------------

#[tokio::test]
async fn override_endpoint_uses_node_when_healthy() {
    let t = MockTransport::new(
        Box::new(|url: &str| {
            assert!(
                url.starts_with("http://my-node:1234"),
                "override host: {url}"
            );
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(ok(b"custom".to_vec(), Some("text/plain")))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let opts = ResolveOptions {
        endpoint: Some("http://my-node:1234".into()),
        ..Default::default()
    };
    let data = success(
        Resolver::with_options(t, opts)
            .resolve(&rootless_urn("index.html"))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"custom");
}

#[tokio::test]
async fn override_unreachable_does_not_leak_to_public_rpc() {
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|url: &str, _b: &str| {
            assert!(!url.contains("rpc.dig.net"), "must not leak to public rpc");
            Err(transport_err())
        }),
    );
    let opts = ResolveOptions {
        endpoint: Some("http://my-node:1234".into()),
        ..Default::default()
    };
    let outcome = Resolver::with_options(t, opts)
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::Unreachable);
}

// --- outcome accessors -----------------------------------------------------

#[test]
fn outcome_accessors() {
    let ok = ResolveOutcome::Success(ResolvedData::new(vec![1, 2], "image/png".into()));
    assert!(ok.is_success());
    assert_eq!(ok.kind(), "success");
    assert_eq!(ok.data().unwrap().bytes, vec![1, 2]);

    assert_eq!(ResolveOutcome::IntegrityFailure.kind(), "integrity_failure");
    assert!(!ResolveOutcome::IntegrityFailure.is_success());
    assert_eq!(ResolveOutcome::Unreachable.kind(), "unreachable");

    // Success renders its verified content verbatim.
    let rendered = ok.render("https://dig.net");
    assert_eq!(rendered.bytes, vec![1, 2]);
    assert_eq!(rendered.content_type, "image/png");
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
