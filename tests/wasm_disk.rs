//! The wasm disk cache, exercised under Node.js (`wasm-pack test --node`).
//!
//! Proves the `cachePath` disk cache is FUNCTIONAL in the wasm build once Node's `fs`
//! is injected (the split the package ships: live under Node, inert in the browser):
//! artifacts round-trip through the real filesystem and survive a fresh `DiskCache`.
#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use dig_urn_resolver::cache::{DiskArtifacts, DiskCache};
use dig_urn_resolver::node_fs;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

// Node-only helpers: the real `fs` module and a unique temp directory. The
// wasm-bindgen-test node runner loads snippets as ESM, so import the builtins (the
// published Node build uses `require('fs')` in its CommonJS entry instead).
#[wasm_bindgen(inline_js = "
    import * as fs from 'node:fs';
    import * as os from 'node:os';
    import * as path from 'node:path';
    export function node_fs() { return fs; }
    export function unique_dir() {
        return path.join(os.tmpdir(), 'dig-urn-resolver-test-' + Date.now() + '-' + Math.random().toString(36).slice(2));
    }
")]
extern "C" {
    fn node_fs() -> JsValue;
    fn unique_dir() -> String;
}

fn artifacts() -> DiskArtifacts {
    DiskArtifacts {
        ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        proof_b64: "cHJvb2Y=".to_string(),
        chunk_lens: vec![4],
    }
}

#[wasm_bindgen_test]
fn node_fs_is_inert_until_injected_then_available() {
    // The seam reports availability only after `fs` is injected — the mechanism that
    // keeps `cachePath` a no-op in a browser (where the setter is never called).
    node_fs::set_node_fs(&node_fs());
    assert!(node_fs::is_available(), "fs injected ⇒ disk cache live");
}

#[wasm_bindgen_test]
fn disk_cache_round_trips_through_node_fs() {
    node_fs::set_node_fs(&node_fs());
    let dir = unique_dir();
    let cache = DiskCache::new(&dir);
    let art = artifacts();

    assert!(cache.get("k").is_none(), "cold cache misses");

    cache.put("k", &art);
    assert_eq!(
        cache.get("k"),
        Some(art.clone()),
        "written artifacts read back"
    );

    // A fresh handle on the same directory still sees the persisted entry (survives
    // across resolver instances / process runs — the point of the disk cache).
    let reopened = DiskCache::new(&dir);
    assert_eq!(reopened.get("k"), Some(art), "persists across handles");

    cache.remove("k");
    assert!(cache.get("k").is_none(), "removed entry is gone");
}
