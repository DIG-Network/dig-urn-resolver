//! A synchronous filesystem seam for the wasm build, backed by Node's `fs`.
//!
//! The disk cache ([`crate::cache::DiskCache`]) needs to persist verifiable artifacts
//! across process runs. In a browser there is no filesystem, so this seam stays
//! INERT (every operation is a no-op / miss) until a host injects Node's `fs`.
//!
//! # Why injection, not a static import
//!
//! The SAME wasm+`wasm-bindgen` build serves both the browser (`web`) and Node
//! (`nodejs`) targets, so a static `#[wasm_bindgen(module = "fs")]` import would leak
//! `import ... from 'fs'` into the browser glue and break bundlers. Instead the
//! assembled Node entry (a CommonJS wrapper) calls [`set_node_fs`] with Node's `fs`
//! at load time; the browser entry never does, so `cachePath` is a harmless no-op
//! clientside while working fully under Node — exactly the intended split.

use js_sys::{Function, Object, Reflect, Uint8Array};
use std::cell::RefCell;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// The four synchronous `fs` functions the disk cache needs, once injected.
struct NodeFs {
    read_file_sync: Function,
    write_file_sync: Function,
    mkdir_sync: Function,
    unlink_sync: Function,
}

thread_local! {
    /// The injected Node `fs` (browser: forever `None` ⇒ the cache is inert).
    static NODE_FS: RefCell<Option<NodeFs>> = const { RefCell::new(None) };
}

/// Inject Node's `fs` module so the disk cache becomes functional. Called ONCE by the
/// package's CommonJS Node entry with `require('fs')`; never called in the browser.
///
/// Exported to JS as `__dig_set_node_fs`. Missing methods ⇒ the cache stays inert
/// (a malformed injection can never crash a resolve).
#[wasm_bindgen(js_name = __dig_set_node_fs)]
pub fn set_node_fs(fs: &JsValue) {
    let method = |name: &str| -> Option<Function> {
        Reflect::get(fs, &JsValue::from_str(name))
            .ok()
            .and_then(|v| v.dyn_into::<Function>().ok())
    };
    if let (Some(read_file_sync), Some(write_file_sync), Some(mkdir_sync), Some(unlink_sync)) = (
        method("readFileSync"),
        method("writeFileSync"),
        method("mkdirSync"),
        method("unlinkSync"),
    ) {
        NODE_FS.with(|slot| {
            *slot.borrow_mut() = Some(NodeFs {
                read_file_sync,
                write_file_sync,
                mkdir_sync,
                unlink_sync,
            });
        });
    }
}

/// Whether a Node `fs` has been injected (⇒ disk caching is live). `false` in the
/// browser, where the disk cache is a no-op and the in-memory cache applies.
pub fn is_available() -> bool {
    NODE_FS.with(|slot| slot.borrow().is_some())
}

/// `fs.mkdirSync(dir, { recursive: true })` — best-effort (ignores "already exists").
pub fn mkdir_all(dir: &str) {
    NODE_FS.with(|slot| {
        if let Some(fs) = slot.borrow().as_ref() {
            let opts = Object::new();
            let _ = Reflect::set(&opts, &JsValue::from_str("recursive"), &JsValue::TRUE);
            let _ = fs
                .mkdir_sync
                .call2(&JsValue::NULL, &JsValue::from_str(dir), &opts);
        }
    });
}

/// `fs.readFileSync(path)` → the file bytes, or `None` on miss / unreadable (a thrown
/// `ENOENT` is caught and treated as a cache miss, never a crash).
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    NODE_FS.with(|slot| {
        let borrow = slot.borrow();
        let fs = borrow.as_ref()?;
        let buffer = fs
            .read_file_sync
            .call1(&JsValue::NULL, &JsValue::from_str(path))
            .ok()?;
        // A Node Buffer IS a Uint8Array subclass, so this cast holds.
        buffer.dyn_into::<Uint8Array>().ok().map(|arr| arr.to_vec())
    })
}

/// `fs.writeFileSync(path, bytes)` — best-effort (ignores I/O errors).
pub fn write_file(path: &str, bytes: &[u8]) {
    NODE_FS.with(|slot| {
        if let Some(fs) = slot.borrow().as_ref() {
            let data = Uint8Array::from(bytes);
            let _ = fs
                .write_file_sync
                .call2(&JsValue::NULL, &JsValue::from_str(path), &data);
        }
    });
}

/// `fs.unlinkSync(path)` — best-effort (ignores a missing file).
pub fn remove_file(path: &str) {
    NODE_FS.with(|slot| {
        if let Some(fs) = slot.borrow().as_ref() {
            let _ = fs
                .unlink_sync
                .call1(&JsValue::NULL, &JsValue::from_str(path));
        }
    });
}
