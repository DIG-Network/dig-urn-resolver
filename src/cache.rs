//! Response caching — an ADDITIVE layer in front of `resolve` that NEVER weakens
//! fail-closed. URNs are content-addressed → immutable → cacheable.
//!
//! # What is safe to cache
//!
//! * **Only VERIFIED `Success` bytes.** An `IntegrityFailure` / `Unreachable` /
//!   `NotFound` / any error outcome is NEVER cached (a cached `Unreachable` would
//!   block recovery when the network returns; caching a failure is simply wrong).
//! * **Keyed by the content-addressed identity** `storeId:root:resourceKey:salt`
//!   with the CONCRETE resolved root — never the raw request URN. A root-pinned URN
//!   is immutable; a rootless URN is cached under the root the resolve actually
//!   produced (from the node's `X-Dig-Root`), so it can't go stale when the store
//!   advances.
//!
//! # Two tiers, two trust levels
//!
//! * **Memory (LRU, bounded):** process-trusted — it only ever holds what THIS
//!   process already verified THIS run, so a memory hit may skip re-verification.
//! * **Disk (optional, native):** UNTRUSTED storage. It caches the *verifiable
//!   artifacts* (ciphertext + inclusion proof + chunk lengths), NOT plaintext, so a
//!   disk hit is RE-VERIFIED against the URN's chain-anchored root before use (see
//!   [`DiskArtifacts`]). A tampered on-disk file therefore FAILS verification →
//!   `IntegrityFailure`, and its bytes are never served. Filenames are the SHA-256
//!   of the identity (content-addressed, no path-traversal from the URN).

use crate::resolver::ResolvedData;
use std::cell::RefCell;
use std::collections::HashMap;

/// The content-addressed cache identity: `storeId:root:resourceKey:salt`. `root` MUST
/// be the CONCRETE resolved root (pinned root, or the node's `X-Dig-Root`).
pub fn content_id(store_id: &str, root: &str, resource_key: &str, salt: Option<&str>) -> String {
    format!("{store_id}:{root}:{resource_key}:{}", salt.unwrap_or(""))
}

/// The verifiable artifacts of an rpc-path fetch — enough to RE-VERIFY the bytes
/// from scratch against the URN's root. Persisted to the disk cache so a disk hit is
/// re-verified (never trusted blindly).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiskArtifacts {
    /// The served ciphertext (raw bytes).
    pub ciphertext: Vec<u8>,
    /// The base64 merkle inclusion proof.
    pub proof_b64: String,
    /// Per-chunk ciphertext byte lengths (empty ⇒ single chunk).
    pub chunk_lens: Vec<u32>,
}

// ---------------------------------------------------------------------------
// In-memory LRU (process-trusted)
// ---------------------------------------------------------------------------

/// A bounded in-memory LRU of verified plaintext, keyed by [`content_id`]. Bounded
/// by BOTH an entry count and a total-byte budget (this ends up in a wallet — no
/// unbounded growth). Process-trusted: a hit returns without re-verification.
pub struct MemoryCache {
    max_entries: usize,
    max_bytes: usize,
    inner: RefCell<Inner>,
}

struct Inner {
    tick: u64,
    bytes: usize,
    map: HashMap<String, Entry>,
}

struct Entry {
    last_used: u64,
    data: ResolvedData,
}

impl MemoryCache {
    /// A cache bounded to `max_entries` entries and `max_bytes` total bytes.
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        MemoryCache {
            max_entries,
            max_bytes,
            inner: RefCell::new(Inner {
                tick: 0,
                bytes: 0,
                map: HashMap::new(),
            }),
        }
    }

    /// A verified hit (bumps recency), or `None`.
    pub fn get(&self, id: &str) -> Option<ResolvedData> {
        let mut inner = self.inner.borrow_mut();
        inner.tick += 1;
        let tick = inner.tick;
        let entry = inner.map.get_mut(id)?;
        entry.last_used = tick;
        Some(entry.data.clone())
    }

    /// Insert verified plaintext, evicting the least-recently-used entries until both
    /// bounds hold. An entry larger than the whole byte budget is simply not cached.
    pub fn put(&self, id: String, data: ResolvedData) {
        let size = data.bytes.len();
        if self.max_entries == 0 || size > self.max_bytes {
            return;
        }
        let mut inner = self.inner.borrow_mut();
        inner.tick += 1;
        let tick = inner.tick;
        if let Some(prev) = inner.map.insert(
            id,
            Entry {
                last_used: tick,
                data,
            },
        ) {
            inner.bytes -= prev.data.bytes.len();
        }
        inner.bytes += size;
        self.evict(&mut inner);
    }

    /// Evict LRU entries until within both bounds.
    fn evict(&self, inner: &mut Inner) {
        while inner.map.len() > self.max_entries || inner.bytes > self.max_bytes {
            let Some(victim) = inner
                .map
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(removed) = inner.map.remove(&victim) {
                inner.bytes -= removed.data.bytes.len();
            }
        }
    }
}

/// The default memory-cache bounds: 256 entries or 32 MiB, whichever binds first.
pub const DEFAULT_MEMORY_ENTRIES: usize = 256;
/// See [`DEFAULT_MEMORY_ENTRIES`].
pub const DEFAULT_MEMORY_BYTES: usize = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Disk cache (UNTRUSTED storage — always re-verified on read)
//
// Two backends behind ONE interface (`new`/`get`/`put`/`remove`): `std::fs` for the
// native build, and Node's `fs` (via the injected `node_fs` seam) for the wasm build
// running under Node. In the browser the wasm backend is inert — see `node_fs`.
// ---------------------------------------------------------------------------

#[cfg(feature = "native")]
pub use disk::DiskCache;

#[cfg(all(feature = "wasm", not(feature = "native")))]
pub use disk_wasm::DiskCache;

#[cfg(feature = "native")]
mod disk {
    use super::DiskArtifacts;
    use digstore_core::hash::sha256;
    use std::path::PathBuf;

    /// A content-addressed disk cache of [`DiskArtifacts`]. UNTRUSTED: every read is
    /// re-verified by the caller against the URN's root before use.
    pub struct DiskCache {
        dir: PathBuf,
    }

    impl DiskCache {
        /// Open (creating the directory) a disk cache rooted at `dir`.
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            let dir = dir.into();
            let _ = std::fs::create_dir_all(&dir);
            DiskCache { dir }
        }

        /// The content-addressed file path for an identity — `SHA-256(id)` hex, so a
        /// malicious URN can never traverse out of the cache directory.
        fn path(&self, id: &str) -> PathBuf {
            self.dir
                .join(format!("{}.json", sha256(id.as_bytes()).to_hex()))
        }

        /// Load the stored artifacts for `id`, or `None` on miss / unreadable /
        /// malformed (a corrupt envelope is a miss, not a crash).
        pub fn get(&self, id: &str) -> Option<DiskArtifacts> {
            let raw = std::fs::read(self.path(id)).ok()?;
            serde_json::from_slice(&raw).ok()
        }

        /// Persist the verifiable artifacts for `id` (best-effort; ignore I/O errors).
        pub fn put(&self, id: &str, artifacts: &DiskArtifacts) {
            if let Ok(bytes) = serde_json::to_vec(artifacts) {
                let _ = std::fs::write(self.path(id), bytes);
            }
        }

        /// Remove a (failed-verification / stale) entry, best-effort.
        pub fn remove(&self, id: &str) {
            let _ = std::fs::remove_file(self.path(id));
        }
    }
}

#[cfg(all(feature = "wasm", not(feature = "native")))]
mod disk_wasm {
    use super::DiskArtifacts;
    use crate::node_fs;
    use digstore_core::hash::sha256;

    /// A content-addressed disk cache backed by Node's `fs` (the wasm build). Mirrors
    /// the native [`super::disk::DiskCache`] byte-for-byte on disk (a `SHA-256(id).json`
    /// envelope of [`DiskArtifacts`]), so the two backends are interchangeable and a
    /// cache written by one is readable by the other. UNTRUSTED: every read is
    /// re-verified by the caller against the URN's root. In the browser, `node_fs` is
    /// inert, so `get` always misses and `put`/`remove` are no-ops.
    pub struct DiskCache {
        dir: String,
    }

    impl DiskCache {
        /// Open (creating the directory under Node) a disk cache rooted at `dir`.
        pub fn new(dir: impl AsRef<str>) -> Self {
            let dir = dir.as_ref().trim_end_matches('/').to_string();
            node_fs::mkdir_all(&dir);
            DiskCache { dir }
        }

        /// The content-addressed file path for an identity — `SHA-256(id)` hex, so a
        /// malicious URN can never traverse out of the cache directory.
        fn path(&self, id: &str) -> String {
            format!("{}/{}.json", self.dir, sha256(id.as_bytes()).to_hex())
        }

        /// Load the stored artifacts for `id`, or `None` on miss / unreadable /
        /// malformed (a corrupt envelope is a miss, not a crash).
        pub fn get(&self, id: &str) -> Option<DiskArtifacts> {
            let raw = node_fs::read_file(&self.path(id))?;
            serde_json::from_slice(&raw).ok()
        }

        /// Persist the verifiable artifacts for `id` (best-effort; ignore I/O errors).
        pub fn put(&self, id: &str, artifacts: &DiskArtifacts) {
            if let Ok(bytes) = serde_json::to_vec(artifacts) {
                node_fs::write_file(&self.path(id), &bytes);
            }
        }

        /// Remove a (failed-verification / stale) entry, best-effort.
        pub fn remove(&self, id: &str) {
            node_fs::remove_file(&self.path(id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::ResolvedData;

    fn data(n: usize) -> ResolvedData {
        ResolvedData::new(vec![0u8; n], "image/png".into())
    }

    #[test]
    fn content_id_is_stable_and_distinguishes_salt_and_root() {
        assert_eq!(
            content_id("s", "r", "a.png", None),
            content_id("s", "r", "a.png", None)
        );
        assert_ne!(
            content_id("s", "r1", "a.png", None),
            content_id("s", "r2", "a.png", None)
        );
        assert_ne!(
            content_id("s", "r", "a.png", Some("aa")),
            content_id("s", "r", "a.png", None)
        );
    }

    #[test]
    fn memory_cache_hits_and_misses() {
        let c = MemoryCache::new(8, 1 << 20);
        assert!(c.get("k").is_none());
        c.put("k".into(), data(10));
        assert_eq!(c.get("k").unwrap().bytes.len(), 10);
    }

    #[test]
    fn memory_cache_evicts_lru_at_entry_cap() {
        let c = MemoryCache::new(2, 1 << 20);
        c.put("a".into(), data(1));
        c.put("b".into(), data(1));
        let _ = c.get("a"); // 'a' now most-recently-used, 'b' is LRU
        c.put("c".into(), data(1)); // evicts 'b'
        assert!(c.get("a").is_some());
        assert!(c.get("c").is_some());
        assert!(c.get("b").is_none(), "LRU entry evicted");
    }

    #[test]
    fn memory_cache_evicts_at_byte_cap() {
        let c = MemoryCache::new(100, 100);
        c.put("a".into(), data(60));
        c.put("b".into(), data(60)); // total 120 > 100 → evict 'a'
        assert!(c.get("a").is_none());
        assert!(c.get("b").is_some());
        // An oversized entry is simply not cached.
        c.put("big".into(), data(200));
        assert!(c.get("big").is_none());
    }
}
