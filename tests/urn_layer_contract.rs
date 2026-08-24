//! The TWO-LAYER `urn:dig:` contract, made testable.
//!
//! The ecosystem runs several independent URN parsers and they disagree. The
//! disagreements are not all bugs: most of them are two DIFFERENT layers being compared
//! as if they were one. This battery states the boundary and pins it from both sides.
//!
//! | layer | entry point | job | `?salt=` |
//! |---|---|---|---|
//! | **edge** | [`ParsedUrn::parse`] | split a USER-SUPPLIED string into `{urn, salt}` | PEELED off the tail |
//! | **canonical** | [`DigUrn::parse`] | URN identity + key derivation | NOT special — literal resource bytes |
//!
//! The frozen corpus (`fixtures/urn_conformance.json`) is a **canonical-layer** corpus:
//! its `input` column is an already-peeled canonical URN, which is why it carries the
//! vector `query_suffix_is_part_of_resource_not_salt`. Read as an EDGE-layer corpus that
//! vector states the opposite of what every shipped edge parser does, so the layer label
//! is load-bearing, not bookkeeping.
//!
//! The rule that dissolves the salt-length contradiction between the two fixture
//! families: **parse EXTRACTS, derive VALIDATES.** The edge parser returns whatever hex
//! run it found; the 64-hex/32-byte requirement is enforced where the salt becomes key
//! material, and it surfaces as a coded, catchable error — never a panic.
//!
//! Before this battery existed the corpus's frozen `canonical` / `resource_key` /
//! `retrieval_key_hex` columns were read by NOTHING: `cross_parser_equivalence` consumes
//! only `input`, so three implementations could have agreed on a wrong key and stayed
//! green, and the nine `invalid[]` rows were never exercised at all.

use dig_urn_protocol::DigUrn;
use dig_urn_resolver::{crypto, ParsedUrn, ResolveError};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn corpus() -> Value {
    serde_json::from_str(include_str!("fixtures/urn_conformance.json"))
        .expect("frozen corpus is valid JSON")
}

// ---------------------------------------------------------------------------
// The canonical layer — every frozen column is now load-bearing.
// ---------------------------------------------------------------------------

/// Each valid vector's FROZEN expectations must be reproduced by the canonical parser,
/// field by field. This is what makes the corpus a conformance corpus rather than a list
/// of inputs: a self-consistent-but-wrong derivation across all three Rust parsers would
/// still fail here, because the expected values are frozen text, not recomputed.
#[test]
fn canonical_layer_reproduces_every_frozen_column() {
    let corpus = corpus();
    let vectors = corpus["valid"].as_array().expect("corpus has valid[]");
    assert_eq!(
        vectors.len(),
        9,
        "corpus width changed — re-verify the layer contract before re-pinning"
    );

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector has a name");
        let input = vector["input"].as_str().expect("vector has an input");
        let urn = DigUrn::parse(input).unwrap_or_else(|e| panic!("{name}: must parse: {e}"));

        assert_eq!(urn.chain, vector["chain"].as_str().unwrap(), "{name}: chain");
        assert_eq!(
            urn.store_id_hex(),
            vector["store_id_hex"].as_str().unwrap(),
            "{name}: store id"
        );
        assert_eq!(
            urn.root_hex().as_deref(),
            vector["root_hash_hex"].as_str(),
            "{name}: root (None vs Some is part of the contract)"
        );
        // The three-state resource key: absent / empty / concrete. Collapsing the first
        // two derives a different key, which is contradiction (b) on the epic.
        assert_eq!(
            urn.resource_key.as_deref(),
            vector["resource_key"].as_str(),
            "{name}: resource key three-state"
        );
        assert_eq!(
            urn.canonical(),
            vector["canonical"].as_str().unwrap(),
            "{name}: canonical form"
        );
        assert_eq!(
            urn.retrieval_key_hex(),
            vector["retrieval_key_hex"].as_str().unwrap(),
            "{name}: retrieval key = SHA-256(canonical)"
        );
    }
}

/// The ABUSE half. Nine rows describe strings the grammar MUST reject; nothing exercised
/// them before. Both layers must refuse all nine — a widened parser is otherwise
/// invisible, because every accept-side test keeps passing when a parser accepts more.
#[test]
fn both_layers_reject_every_invalid_vector() {
    let corpus = corpus();
    let vectors = corpus["invalid"].as_array().expect("corpus has invalid[]");
    assert_eq!(vectors.len(), 9, "the abuse corpus lost or gained rows");

    for vector in vectors {
        let name = vector["name"].as_str().expect("vector has a name");
        let input = vector["input"].as_str().expect("vector has an input");
        assert!(
            DigUrn::parse(input).is_err(),
            "{name}: canonical layer must reject {input:?}"
        );
        assert!(
            ParsedUrn::parse(input).is_err(),
            "{name}: edge layer must reject {input:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The layer boundary itself.
// ---------------------------------------------------------------------------

/// The discriminating fixture. On a URN carrying a `?salt=` tail the two layers MUST
/// disagree — the edge peels it, the canonical layer keeps it as resource bytes — and
/// therefore derive different wire keys. A control vector with no `?salt=` pins that they
/// otherwise agree, so this cannot pass by both layers being equally broken.
#[test]
fn edge_layer_peels_salt_and_canonical_layer_does_not() {
    let store = "1111111111111111111111111111111111111111111111111111111111111111";
    let salted = format!("urn:dig:chia:{store}/index.html?salt=deadbeef");

    // Canonical layer: `?salt=` is not special. Matches the frozen vector
    // `query_suffix_is_part_of_resource_not_salt`.
    let canonical = DigUrn::parse(&salted).expect("canonical layer parses the salted string");
    assert_eq!(
        canonical.resource_key.as_deref(),
        Some("index.html?salt=deadbeef"),
        "canonical layer must keep the query suffix inside the resource"
    );

    // Edge layer: the salt is peeled OUT of the resource.
    let edge = ParsedUrn::parse(&salted).expect("edge layer parses the salted string");
    assert_eq!(edge.salt.as_deref(), Some("deadbeef"), "edge layer extracts");
    assert_eq!(
        edge.resource_key(),
        "index.html",
        "edge layer must not leave the salt inside the resource"
    );

    // ...so the two layers derive DIFFERENT keys for the same string. This inequality is
    // the boundary: it collapses the moment either layer adopts the other's salt policy.
    assert_ne!(
        edge.retrieval_key_hex(),
        canonical.content_key_hex(),
        "peeling the salt must change the derived key, or the boundary does not exist"
    );

    // CONTROL — an honest, salt-free vector where the layers MUST agree.
    let plain = format!("urn:dig:chia:{store}/index.html");
    assert_eq!(
        ParsedUrn::parse(&plain).unwrap().retrieval_key_hex(),
        DigUrn::parse(&plain).unwrap().content_key_hex(),
        "without a salt tail the two layers must derive the same key"
    );
}

/// **Parse EXTRACTS, derive VALIDATES** — the rule that dissolves the salt-length
/// contradiction. A short salt is a successful PARSE (matching every shipped edge parser
/// and the dig-sdk conformance rows that pin `salt=aaaa` as valid) and a coded, catchable
/// FAILURE at derive time. The failure must be a typed error, never a panic: the same
/// path in `dig-client-wasm` raises an unhandled `JsError`, which is contradiction (c) on
/// the epic and is what this crate must not reproduce.
#[test]
fn short_salt_parses_at_the_edge_and_fails_coded_at_derive() {
    let store = "1111111111111111111111111111111111111111111111111111111111111111";

    let short = ParsedUrn::parse(&format!("urn:dig:chia:{store}/index.html?salt=aaaa"))
        .expect("a short salt is a successful edge PARSE — extraction, not validation");
    assert_eq!(short.salt.as_deref(), Some("aaaa"));

    match crypto::decrypt(&short, b"any ciphertext", &[]) {
        Err(ResolveError::Parse(msg)) => assert!(
            msg.contains("64 hex"),
            "the coded failure must name the 64-hex rule, got {msg:?}"
        ),
        other => panic!("derive must reject a short salt with a coded Parse error, got {other:?}"),
    }

    // CONTROL — a well-formed 64-hex salt clears the derive-layer validator, so the test
    // above is measuring salt LENGTH and not merely that decryption of junk fails.
    let full_salt = "aa".repeat(32);
    let full = ParsedUrn::parse(&format!("urn:dig:chia:{store}/index.html?salt={full_salt}"))
        .expect("a 64-hex salt parses");
    assert!(
        !matches!(
            crypto::decrypt(&full, b"any ciphertext", &[]),
            Err(ResolveError::Parse(_))
        ),
        "a 64-hex salt must clear the salt validator (it may still fail the AEAD)"
    );
}

/// Contradiction (a), the chain token, decided in favour of the WIDER grammar and pinned
/// so nobody narrows it by accident. `.dig` content is permanently on-chain-anchored
/// (CLAUDE.md §5.1), so a `urn:dig:mainnet:…` string already published must keep
/// resolving; rejecting it would be a breaking change wearing a bug-fix's clothes. The
/// abuse side — an EMPTY chain token — is still refused, so "wider" is not "anything".
#[test]
fn non_canonical_chain_labels_stay_accepted_but_an_empty_one_does_not() {
    let store = "1111111111111111111111111111111111111111111111111111111111111111";
    for chain in ["chia", "mainnet", "testnet"] {
        let urn = ParsedUrn::parse(&format!("urn:dig:{chain}:{store}/a"))
            .unwrap_or_else(|e| panic!("{chain} label must keep resolving: {e}"));
        assert_eq!(urn.urn.chain, chain);
    }
    assert!(
        ParsedUrn::parse(&format!("urn:dig::{store}/a")).is_err(),
        "an empty chain token is still invalid"
    );
}

/// Contradiction (b), resource optionality, decided in favour of the WIDER grammar: a
/// bare store URN and a trailing slash both resolve, both to the §8.5 default view — so
/// they derive the SAME wire key, while a concrete resource derives a different one.
#[test]
fn absent_and_empty_resources_both_resolve_to_the_default_view() {
    let store = "1111111111111111111111111111111111111111111111111111111111111111";
    let bare = ParsedUrn::parse(&format!("urn:dig:chia:{store}")).expect("bare store resolves");
    let slash =
        ParsedUrn::parse(&format!("urn:dig:chia:{store}/")).expect("trailing slash resolves");
    let named = ParsedUrn::parse(&format!("urn:dig:chia:{store}/other.html")).unwrap();

    assert_eq!(bare.resource_key(), "index.html");
    assert_eq!(slash.resource_key(), "index.html");
    assert_eq!(
        bare.retrieval_key_hex(),
        slash.retrieval_key_hex(),
        "absent and empty must derive ONE key, or the two forms address different content"
    );
    assert_ne!(
        bare.retrieval_key_hex(),
        named.retrieval_key_hex(),
        "control: a concrete resource must still derive its own key"
    );
}

// ---------------------------------------------------------------------------
// The vendored copy.
// ---------------------------------------------------------------------------

/// This corpus is a byte-copy of `dig-urn-protocol`'s, vendored because `include_str!`
/// cannot reach across a crate boundary. A byte-copy is a future divergence unless the
/// divergence is caught, so the VECTOR ROWS are pinned by digest: editing a row here —
/// as opposed to the human-facing `_comment` — fails loudly and forces the change to be
/// made upstream and re-vendored.
#[test]
fn vendored_vector_rows_match_their_pinned_digest() {
    let corpus = corpus();
    let rows = serde_json::json!({
        "canonical_chain": corpus["canonical_chain"],
        "invalid": corpus["invalid"],
        "valid": corpus["valid"],
    });
    let digest = Sha256::digest(serde_json::to_string(&rows).unwrap().as_bytes());
    assert_eq!(
        hex::encode(digest),
        "78fc19444862e6d67b0ab5250c23281a42085d004d766b68050f07db840f5880",
        "the frozen vector rows changed; re-vendor from dig-urn-protocol rather than editing here"
    );
}
