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

/// A dummy pinned root for tests that exercise reachability/protocol paths where the
/// content bytes are irrelevant (the rpc tier requires a pinned root — HOLE B).
const DUMMY_ROOT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn rootless_urn(key: &str) -> String {
    format!("urn:dig:chia:{STORE_HEX}/{key}")
}

fn root_pinned_urn(key: &str, root_hex: &str) -> String {
    format!("urn:dig:chia:{STORE_HEX}:{root_hex}/{key}")
}

/// A root-pinned URN with the dummy root, for rpc reachability/error tests.
fn pinned(key: &str) -> String {
    root_pinned_urn(key, DUMMY_ROOT)
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
                Ok(node_response(pt.clone(), Some(content_type), true))
            } else {
                Err(transport_err())
            }
        }),
        Box::new(|_url, _body| Err(transport_err())),
    )
}

/// A mock with NO node (health probes fail) but a serving rpc gateway. The gateway
/// serves ONLY `dig.getContent` — the resolver must never ask it for a trust root.
fn rpc_serving(fx: RpcFixture) -> MockTransport {
    MockTransport::new(
        Box::new(|_url: &str| Err(transport_err())), // no node: every probe/GET fails
        Box::new(move |_url: &str, body: &str| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            match req["method"].as_str().unwrap() {
                "dig.getContent" => Ok(rpc_ok(get_content_result(&fx))),
                other => panic!(
                    "gateway must not be asked for {other} (trust-root must not come from it)"
                ),
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
async fn bare_store_urn_defaults_to_index_html() {
    // §8.5: a bare store URN (no resource path) resolves to the default view
    // index.html — the node is asked for `/s/<store>/index.html`.
    let t = MockTransport::new(
        Box::new(|url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                assert!(url.ends_with("/index.html"), "default view: {url}");
                Ok(node_response(b"landing".to_vec(), Some("text/html"), true))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let data = success(
        Resolver::new(t)
            .resolve(&format!("urn:dig:chia:{STORE_HEX}"))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"landing");
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
                Ok(node_response(vec![1, 2, 3], None, true))
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
async fn rootless_urn_over_rpc_is_rejected() {
    // HOLE B: with no node, a rootless URN cannot be chain-verified over the
    // untrusted gateway → hard RootRequired, WITHOUT ever asking the gateway for a
    // root (the mock panics if it is). Never data, never unreachable.
    let fx = build_fixture(IMG_KEY, b"whatever", None);
    let err = Resolver::new(rpc_serving(fx))
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::RootRequired));
}

#[tokio::test]
async fn rpc_tier_resolves_root_pinned() {
    let fx = build_fixture(IMG_KEY, b"pinned bytes", None);
    let root = fx.root_hex.clone();
    let data = success(
        Resolver::new(rpc_serving(fx))
            .resolve(&root_pinned_urn(IMG_KEY, &root))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"pinned bytes");
}

#[tokio::test]
async fn rpc_private_store_salt_decrypts_root_pinned() {
    let salt = "cd".repeat(32);
    let fx = build_fixture(IMG_KEY, b"secret art", Some(&salt));
    let root = fx.root_hex.clone();
    let data = success(
        Resolver::new(rpc_serving(fx))
            .resolve(&format!(
                "{}?salt={}",
                root_pinned_urn(IMG_KEY, &root),
                salt
            ))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"secret art");
}

#[tokio::test]
async fn rpc_not_found_when_content_empty() {
    // Root-pinned URN, gateway reports total_length 0 → hard NotFound.
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|_u: &str, _b: &str| Ok(rpc_ok(serde_json::json!({ "total_length": 0 })))),
    );
    let err = Resolver::new(t)
        .resolve(&pinned(IMG_KEY))
        .await
        .unwrap_err();
    assert!(matches!(err, ResolveError::NotFound));
}

// --- IntegrityFailure: fail-CLOSED, distinct, never the bytes --------------

#[tokio::test]
async fn tampered_ciphertext_is_integrity_failure_not_data() {
    let mut tampered = build_fixture(IMG_KEY, b"authentic", None);
    let root = tampered.root_hex.clone();
    // Valid proof + root, but different ciphertext whose leaf won't match.
    tampered.ciphertext_b64 = base64_of(b"tampered ciphertext bytes!!");
    tampered.total_length = 27;
    tampered.chunk_lens = vec![27];
    let outcome = Resolver::new(rpc_serving(tampered))
        .resolve(&root_pinned_urn(IMG_KEY, &root))
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
    let root = fx.root_hex.clone();
    let wrong_salt = "ef".repeat(32);
    let outcome = Resolver::new(rpc_serving(fx))
        .resolve(&format!(
            "{}?salt={}",
            root_pinned_urn(IMG_KEY, &root),
            wrong_salt
        ))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::IntegrityFailure);
}

#[tokio::test]
async fn integrity_failure_renders_security_page_never_the_bytes() {
    let mut tampered = build_fixture(IMG_KEY, b"authentic", None);
    let root = tampered.root_hex.clone();
    tampered.ciphertext_b64 = base64_of(b"evil");
    tampered.total_length = 4;
    tampered.chunk_lens = vec![4];
    let rendered = Resolver::new(rpc_serving(tampered))
        .resolve_rendered(&root_pinned_urn(IMG_KEY, &root))
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
        .resolve(&pinned(IMG_KEY))
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
    let outcome = Resolver::new(t).resolve(&pinned(IMG_KEY)).await.unwrap();
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
        .resolve_rendered(&pinned(IMG_KEY))
        .await
        .unwrap();
    let html = String::from_utf8(rendered.bytes).unwrap();
    assert!(html.contains("dig://home"));
}

// --- HOLE A: node trust is loopback-only -----------------------------------

#[tokio::test]
async fn node_without_x_dig_verified_is_fail_closed() {
    // A loopback node serves 200 bytes but omits X-Dig-Verified → the node did not
    // attest verification → fail closed (IntegrityFailure), never returned as data.
    let t = MockTransport::new(
        Box::new(|url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(node_response(
                    b"unverified".to_vec(),
                    Some("text/plain"),
                    false,
                ))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let outcome = Resolver::new(t)
        .resolve(&rootless_urn(IMG_KEY))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::IntegrityFailure);
}

#[tokio::test]
async fn override_remote_host_uses_verified_rpc_not_node() {
    // HOLE A: an override at a REMOTE host must NOT be trusted as a node. It is
    // routed to the client-verified rpc path — the node `/s/` + `/health` GETs are
    // never called; only the verified rpc post is.
    let fx = build_fixture(IMG_KEY, b"verified art", None);
    let root = fx.root_hex.clone();
    let t = MockTransport::new(
        Box::new(|url: &str| panic!("remote override must not use the node path: {url}")),
        Box::new(move |url: &str, body: &str| {
            assert!(
                url.starts_with("http://evil.example.com"),
                "override base: {url}"
            );
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            match req["method"].as_str().unwrap() {
                "dig.getContent" => Ok(rpc_ok(get_content_result(&fx))),
                other => panic!("unexpected method {other}"),
            }
        }),
    );
    let opts = ResolveOptions {
        endpoint: Some("http://evil.example.com".into()),
        ..Default::default()
    };
    let data = success(
        Resolver::with_options(t, opts)
            .resolve(&root_pinned_urn(IMG_KEY, &root))
            .await
            .unwrap(),
    );
    // The bytes came back ONLY because they verified against the pinned root.
    assert_eq!(data.bytes, b"verified art");
}

#[tokio::test]
async fn override_loopback_host_may_use_node() {
    // A loopback override IS eligible for the node path (the user's own machine).
    let t = MockTransport::new(
        Box::new(|url: &str| {
            assert!(
                url.starts_with("http://127.0.0.1:9778"),
                "loopback base: {url}"
            );
            Ok(node_response(b"local".to_vec(), Some("text/plain"), true))
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let opts = ResolveOptions {
        endpoint: Some("http://127.0.0.1:9778".into()),
        ..Default::default()
    };
    let data = success(
        Resolver::with_options(t, opts)
            .resolve(&rootless_urn("index.html"))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"local");
}

#[tokio::test]
async fn override_remote_unreachable_does_not_leak_to_public_rpc() {
    // A remote override that is fully down → Unreachable, never a silent fallback to
    // rpc.dig.net (the override is authoritative). Root-pinned so it reaches the rpc
    // transport (the remote override IS an rpc endpoint) before failing.
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(|url: &str, _b: &str| {
            assert!(!url.contains("rpc.dig.net"), "must not leak to public rpc");
            Err(transport_err())
        }),
    );
    let opts = ResolveOptions {
        endpoint: Some("http://my-node.example.com:1234".into()),
        ..Default::default()
    };
    let outcome = Resolver::with_options(t, opts)
        .resolve(&pinned(IMG_KEY))
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

// --- node CIPHERTEXT path (client verify+decrypt, salt on both tiers) ------

#[tokio::test]
async fn node_ciphertext_response_is_verified_and_decrypted() {
    // A loopback node that returns CIPHERTEXT (not plaintext) must be client-side
    // verified + decrypted, NOT trusted blindly.
    let fx = build_fixture(IMG_KEY, b"\x89PNG node ciphertext", None);
    let root = fx.root_hex.clone();
    let t = MockTransport::new(
        Box::new(move |url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(node_ciphertext_response(&fx))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let data = success(
        Resolver::new(t)
            .resolve(&root_pinned_urn(IMG_KEY, &root))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"\x89PNG node ciphertext");
}

#[tokio::test]
async fn salted_urn_decrypts_on_node_ciphertext_path() {
    let salt = "cd".repeat(32);
    let fx = build_fixture(IMG_KEY, b"salted node art", Some(&salt));
    let root = fx.root_hex.clone();
    let t = MockTransport::new(
        Box::new(move |url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(node_ciphertext_response(&fx))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let data = success(
        Resolver::new(t)
            .resolve(&format!(
                "{}?salt={}",
                root_pinned_urn(IMG_KEY, &root),
                salt
            ))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"salted node art");
}

#[tokio::test]
async fn wrong_salt_on_node_ciphertext_path_is_integrity_failure() {
    // Ciphertext committed WITHOUT salt; resolved WITH a salt over the node
    // ciphertext path → decrypt tag fails → fail-closed IntegrityFailure.
    let fx = build_fixture(IMG_KEY, b"art", None);
    let root = fx.root_hex.clone();
    let t = MockTransport::new(
        Box::new(move |url: &str| {
            if url.ends_with("/health") {
                Ok(status(200))
            } else {
                Ok(node_ciphertext_response(&fx))
            }
        }),
        Box::new(|_u, _b| Err(transport_err())),
    );
    let wrong = "ef".repeat(32);
    let outcome = Resolver::new(t)
        .resolve(&format!(
            "{}?salt={}",
            root_pinned_urn(IMG_KEY, &root),
            wrong
        ))
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::IntegrityFailure);
}

// --- caching ---------------------------------------------------------------

#[tokio::test]
async fn second_resolve_is_a_memory_cache_hit_no_network() {
    use std::cell::Cell;
    use std::rc::Rc;
    let fx = build_fixture(IMG_KEY, b"cached bytes", None);
    let root = fx.root_hex.clone();
    let calls = Rc::new(Cell::new(0u32));
    let c = calls.clone();
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())), // no node
        Box::new(move |_u: &str, _b: &str| {
            let n = c.get() + 1;
            c.set(n);
            assert!(n == 1, "2nd network call — expected a cache hit");
            Ok(rpc_ok(get_content_result(&fx)))
        }),
    );
    let r = Resolver::new(t);
    let urn = root_pinned_urn(IMG_KEY, &root);
    assert_eq!(
        success(r.resolve(&urn).await.unwrap()).bytes,
        b"cached bytes"
    );
    assert_eq!(
        success(r.resolve(&urn).await.unwrap()).bytes,
        b"cached bytes"
    );
    assert_eq!(calls.get(), 1, "exactly one network fetch");
}

#[tokio::test]
async fn failures_are_not_cached_and_recovery_retries() {
    use std::cell::Cell;
    use std::rc::Rc;
    let fx = build_fixture(IMG_KEY, b"recovered", None);
    let root = fx.root_hex.clone();
    let up = Rc::new(Cell::new(false));
    let up2 = up.clone();
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())),
        Box::new(move |_u: &str, _b: &str| {
            if up2.get() {
                Ok(rpc_ok(get_content_result(&fx)))
            } else {
                Err(transport_err())
            }
        }),
    );
    let r = Resolver::new(t);
    let urn = root_pinned_urn(IMG_KEY, &root);
    // Network down → Unreachable, and it MUST NOT be cached.
    assert_eq!(r.resolve(&urn).await.unwrap(), ResolveOutcome::Unreachable);
    // Network recovers → a real retry (not a cached failure) → Success.
    up.set(true);
    assert_eq!(success(r.resolve(&urn).await.unwrap()).bytes, b"recovered");
}

#[tokio::test]
async fn tampered_disk_cache_entry_fails_closed() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("dig-urn-resolver-disk-{nanos}"));
    let dir_str = dir.to_string_lossy().to_string();

    let fx = build_fixture(IMG_KEY, b"disk bytes", None);
    let root = fx.root_hex.clone();
    let urn = root_pinned_urn(IMG_KEY, &root);

    // (1) Populate the disk cache with the verifiable artifacts.
    {
        let opts = ResolveOptions {
            cache_path: Some(dir_str.clone()),
            ..Default::default()
        };
        let d = success(
            Resolver::with_options(rpc_serving(fx), opts)
                .resolve(&urn)
                .await
                .unwrap(),
        );
        assert_eq!(d.bytes, b"disk bytes");
    }

    // (2) TAMPER the on-disk ciphertext (leave the proof intact).
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .expect("a disk cache entry was written");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    v["ciphertext"] = serde_json::json!([9, 9, 9, 9, 9, 9]);
    std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();

    // (3) A FRESH resolver (empty memory) whose transport PANICS on any network —
    // it must serve from disk, RE-VERIFY, catch the tamper, and fail closed.
    let t = MockTransport::new(
        Box::new(|u: &str| panic!("must not hit the network (disk hit): {u}")),
        Box::new(|u: &str, _b: &str| panic!("must not hit the network (disk hit): {u}")),
    );
    let opts = ResolveOptions {
        cache_path: Some(dir_str),
        ..Default::default()
    };
    let outcome = Resolver::with_options(t, opts).resolve(&urn).await.unwrap();
    assert_eq!(
        outcome,
        ResolveOutcome::IntegrityFailure,
        "tampered disk bytes must fail closed, never be served"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// --- Node vs browser env degradation ---------------------------------------

#[tokio::test]
async fn browser_cors_blocked_local_probe_falls_back_to_verified_rpc() {
    // Simulate a BROWSER where the local-node `/health` + `/s/` probes throw
    // (CORS-blocked) — every GET errors. The ladder must NOT hard-fail: it degrades
    // to the VERIFIED rpc tier (never to unverified bytes).
    let fx = build_fixture(IMG_KEY, b"rpc bytes", None);
    let root = fx.root_hex.clone();
    let t = MockTransport::new(
        Box::new(|_u: &str| Err(transport_err())), // browser: local probe unavailable
        Box::new(move |_u: &str, body: &str| {
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            match req["method"].as_str().unwrap() {
                "dig.getContent" => Ok(rpc_ok(get_content_result(&fx))),
                other => panic!("unexpected method {other}"),
            }
        }),
    );
    let data = success(
        Resolver::new(t)
            .resolve(&root_pinned_urn(IMG_KEY, &root))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"rpc bytes");
}

#[tokio::test]
async fn unusable_cache_path_degrades_gracefully_never_throws() {
    // A cache_path that can't be used (here: a path that is a FILE, not a directory —
    // stands in for a no-filesystem/browser environment) must NOT throw: the disk
    // layer is best-effort, so resolve still succeeds via memory + network.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let not_a_dir = std::env::temp_dir().join(format!("dig-urn-resolver-notadir-{nanos}"));
    std::fs::write(&not_a_dir, b"x").unwrap();

    let fx = build_fixture(IMG_KEY, b"still resolves", None);
    let root = fx.root_hex.clone();
    let opts = ResolveOptions {
        cache_path: Some(not_a_dir.to_string_lossy().to_string()),
        ..Default::default()
    };
    let data = success(
        Resolver::with_options(rpc_serving(fx), opts)
            .resolve(&root_pinned_urn(IMG_KEY, &root))
            .await
            .unwrap(),
    );
    assert_eq!(data.bytes, b"still resolves");

    let _ = std::fs::remove_file(&not_a_dir);
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
