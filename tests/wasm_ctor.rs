//! The `DigNetwork` constructor's OPTIONS-OBJECT contract, under Node.js
//! (`wasm-pack test --node`).
//!
//! `new DigNetwork(options?)` takes a single, named-field options object — never
//! positional args — so a consumer sets ONLY the fields it needs (no `undefined`
//! placeholders). This proves: all-defaults (no arg), a partial object (one field),
//! a full object (every field), and that an unknown/extra field is ignored. The
//! parsed configuration is observable through the `endpoint` / `connectUrl` /
//! `cachePath` getters.
#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use dig_urn_resolver::wasm::{DigNetwork, DigNetworkOptions};
use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

/// Build a `DigNetworkOptions` JS object from `(key, value)` string pairs.
fn options(pairs: &[(&str, &str)]) -> DigNetworkOptions {
    let obj = Object::new();
    for (k, v) in pairs {
        Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    }
    JsValue::from(obj).unchecked_into()
}

#[wasm_bindgen_test]
fn no_argument_yields_all_defaults() {
    let dig = DigNetwork::new(None);
    assert_eq!(dig.endpoint(), None);
    assert_eq!(dig.connect_url(), None);
    assert_eq!(dig.cache_path(), None);
}

#[wasm_bindgen_test]
fn partial_options_sets_only_the_named_field() {
    // The motivating case: set `cachePath` alone — no `undefined` placeholders.
    let dig = DigNetwork::new(Some(options(&[("cachePath", "/var/cache/dig-urn")])));
    assert_eq!(dig.cache_path().as_deref(), Some("/var/cache/dig-urn"));
    assert_eq!(dig.endpoint(), None, "unset fields keep their defaults");
    assert_eq!(dig.connect_url(), None);
}

#[wasm_bindgen_test]
fn full_options_sets_every_field() {
    let dig = DigNetwork::new(Some(options(&[
        ("endpoint", "http://127.0.0.1:9778"),
        ("connectUrl", "https://dig.net/connect"),
        ("cachePath", "/tmp/dig"),
    ])));
    assert_eq!(dig.endpoint().as_deref(), Some("http://127.0.0.1:9778"));
    assert_eq!(
        dig.connect_url().as_deref(),
        Some("https://dig.net/connect")
    );
    assert_eq!(dig.cache_path().as_deref(), Some("/tmp/dig"));
}

#[wasm_bindgen_test]
fn blank_and_unknown_fields_are_ignored() {
    // A blank string is treated as unset (matches the pre-existing `opt` semantics);
    // an unknown property is tolerated, not rejected.
    let dig = DigNetwork::new(Some(options(&[
        ("endpoint", "   "),
        ("bogus", "ignored"),
        ("cachePath", "/tmp/dig"),
    ])));
    assert_eq!(dig.endpoint(), None, "blank ⇒ unset");
    assert_eq!(dig.cache_path().as_deref(), Some("/tmp/dig"));
}
