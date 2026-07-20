//! Cross-parser equivalence: the resolver's wire/lookup key must be byte-identical
//! across BOTH `urn:dig:` parsers it could use.
//!
//! The ecosystem's wire `retrieval_key` (what the resolver sends and the node indexes)
//! is `SHA-256(canonical_rootless())`. Two crates name that value differently:
//!
//! * `digstore_core::Urn` — the legacy parallel parser: the rootless
//!   `Urn::retrieval_key()`.
//! * `dig_urn_protocol::DigUrn` — the canonical parser: `content_key()`
//!   (its `retrieval_key()` is a DIFFERENT, root-PINNED hash).
//!
//! This test pins the resolver's [`ParsedUrn::retrieval_key_hex`] to that one value
//! from BOTH sides, over the FROZEN conformance corpus (vendored from
//! `dig-urn-protocol/tests/fixtures/urn_conformance.json`). Its teeth: for a
//! root-pinned URN, `content_key` and `retrieval_key` DIFFER, so a naive
//! name-preserving swap of the resolver onto `DigUrn::retrieval_key()` breaks every
//! root-pinned read — and this test fails loudly.

use dig_urn_resolver::ParsedUrn;
use serde_json::Value;

/// The independent oracle: the LEGACY `digstore_core` rootless key — exactly the
/// value the resolver produced before adopting `dig-urn-protocol`. Reproduces the
/// old `ParsedUrn::retrieval_key_hex` derivation (strip salt, drop root, default an
/// empty resource to `index.html`, hash the canonical rootless URN).
fn digstore_rootless_key(input: &str) -> String {
    let core_part = input
        .trim()
        .rsplit_once("?salt=")
        .map(|(head, _)| head)
        .unwrap_or_else(|| input.trim());
    let urn = digstore_core::Urn::parse(core_part).expect("legacy parser accepts a valid vector");
    let effective_resource = match urn.resource_key.as_deref() {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => digstore_core::DEFAULT_RESOURCE_KEY.to_string(),
    };
    let rootless = digstore_core::Urn {
        chain: urn.chain,
        store_id: urn.store_id,
        root_hash: None,
        resource_key: Some(effective_resource),
    };
    rootless.retrieval_key().to_hex()
}

fn corpus() -> Value {
    let raw = include_str!("fixtures/urn_conformance.json");
    serde_json::from_str(raw).expect("frozen corpus is valid JSON")
}

#[test]
fn resolver_key_matches_both_parsers_across_frozen_corpus() {
    let corpus = corpus();
    let valid = corpus["valid"]
        .as_array()
        .expect("corpus has a valid[] array");
    assert!(!valid.is_empty(), "corpus must carry vectors");

    for vector in valid {
        let input = vector["input"].as_str().expect("vector has an input");

        let resolver_key = ParsedUrn::parse(input)
            .expect("resolver parses a valid vector")
            .retrieval_key_hex();

        // Side 1 — the canonical parser: content_key (root-INDEPENDENT).
        let (dig_urn, _salt) = dig_urn_protocol::DigUrn::parse_with_salt(input)
            .expect("canonical parser accepts a valid vector");
        assert_eq!(
            resolver_key,
            dig_urn.content_key_hex(),
            "vector {input}: resolver key must equal dig_urn_protocol content_key"
        );

        // Side 2 — the legacy parser: rootless retrieval key. Proves the two
        // independent parsers agree byte-for-byte on the wire key.
        assert_eq!(
            resolver_key,
            digstore_rootless_key(input),
            "vector {input}: resolver key must equal digstore-core rootless key"
        );
    }
}

/// The trap guard: on every ROOT-PINNED vector the canonical parser's `content_key`
/// (what the resolver MUST use) differs from its `retrieval_key` (the root-pinned
/// hash). A swap onto `retrieval_key` would make this inequality collapse — proving
/// the resolver is bound to `content_key`, never `retrieval_key`.
#[test]
fn root_pinned_urns_prove_content_key_not_retrieval_key() {
    let corpus = corpus();
    let valid = corpus["valid"].as_array().unwrap();

    let mut root_pinned_seen = 0;
    for vector in valid {
        if vector["root_hash_hex"].is_null() {
            continue;
        }
        root_pinned_seen += 1;
        let input = vector["input"].as_str().unwrap();

        let dig_urn = dig_urn_protocol::DigUrn::parse(input).unwrap();
        assert_ne!(
            dig_urn.content_key_hex(),
            dig_urn.retrieval_key_hex(),
            "vector {input}: a root-pinned content_key MUST differ from retrieval_key"
        );

        // And the resolver tracks content_key, NOT the root-pinned retrieval_key.
        let resolver_key = ParsedUrn::parse(input).unwrap().retrieval_key_hex();
        assert_eq!(resolver_key, dig_urn.content_key_hex());
        assert_ne!(
            resolver_key,
            dig_urn.retrieval_key_hex(),
            "vector {input}: resolver key must NOT be the root-pinned retrieval_key"
        );
    }
    assert!(
        root_pinned_seen >= 1,
        "the corpus must exercise at least one root-pinned URN (the trap)"
    );
}
