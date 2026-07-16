# dig-urn-resolver — normative specification

This document is the authoritative contract for `dig-urn-resolver`. An independent
reimplementation MUST behave as specified here. Where this spec references DIG read
semantics it defers to the canonical sources: the Digstore store format + read-crypto
(`digstore-core`), the client→node ladder (superproject CLAUDE.md §5.3), and the
dig-node read wire (`SYSTEM.md`).

## 1. Purpose

Resolve a DIG URN to the bytes + content type of the resource it names, verifying
integrity fail-closed, following the §5.3 node-first ladder.

This crate is the CANONICAL, project-wide client-side URN→data resolver (#668): hub,
the extension, dig-sdk, dig-dns and other consumers converge on it. It sits strictly
UPSTREAM of dig-node — a *client* that talks to a dig-node over the wire (node `/s/` +
`/health`, else the rpc gateway). dig-node performs all heavy lifting (sync, serve,
decrypt, chain anchoring) and MUST NOT depend on this crate. Consumers use the Rust
crate or `@dignetwork/dig-urn-resolver` (JS/wasm); URN resolution is not reimplemented
elsewhere.

## 2. URN grammar

```
urn:dig:chia:<store_id>[:<root>]/<resource_key>[?salt=<hex>]
```

- `store_id` — 64 lowercase hex chars (singleton launcher id). REQUIRED.
- `root` — OPTIONAL 64 hex chars pinning one on-chain generation. The root is the
  trust anchor for inclusion verification ONLY; it is NOT a key input.
- `resource_key` — the path within the store. An ABSENT or empty resource path
  resolves to the §8.5 default view `index.html` (a bare-store or trailing-slash URN
  is NOT rejected — it names the store's landing page).
- `?salt=<hex>` — OPTIONAL out-of-band private-store secret salt.

Parsing MUST reuse the canonical `digstore-core` URN parser for the
`urn:dig:<chain>:<store>[:<root>]/<key>` portion; the `?salt=` suffix is split off
first. A syntactically invalid URN MUST produce a hard parse error.

## 3. Keys (reused, root-independent)

- `retrieval_key = SHA-256(canonical_rootless_urn)`, where the canonical rootless URN
  is `urn:dig:chia:<store_id>/<resource_key>` (root dropped).
- `decryption_key = digstore_core::crypto::derive_decryption_key(canonical_rootless_urn,
  salt?)` (HKDF-SHA256, paper §11).

Both are root-independent so they are stable across generations. Implementations MUST
NOT reimplement these; they MUST call `digstore-core`.

## 4. The §5.3 ladder — node trust is LOOPBACK-ONLY

Resolution order, first that responds wins:

1. explicit endpoint override (from options) — WINS, skips the ladder.
2. `http://dig.local:9778` (node, iff loopback — see below)
3. `http://localhost:9778` (node)
4. `https://rpc.dig.net` (rpc) — the FINAL fallback.

**Node trust (`EndpointKind::Node`) is granted ONLY to an ASSERTED-LOOPBACK host** —
a `127.0.0.0/8` or `::1` literal, the reserved name `localhost`, or `dig.local` iff
it resolves (OS resolver / hosts) to loopback addresses only. The node `/s/` path
returns server-decrypted bytes with NO client-side crypto, so it is sound ONLY on the
user's own machine. EVERY other host — including an explicit override at a remote
host — MUST use the client-verified `Rpc` path. Implementations that cannot resolve
names (e.g. a browser) MUST treat a non-literal, non-`localhost` name as NON-loopback
(no node trust).

- A node tier is selected only when it is an asserted-loopback host AND a cheap `GET
  {base}/health` returns 2xx within a short timeout; otherwise the ladder falls
  through.
- An override is classified by HOST: a loopback host → node surface; ANY other host →
  the client-verified rpc surface. An override MUST NOT silently fall back to the
  public gateway.
- The auto-ladder plan is `[node(first-healthy-loopback), rpc(rpc.dig.net)]` when a
  loopback node tier is healthy, else `[rpc(rpc.dig.net)]`.
- The resolved plan SHOULD be cached per resolver instance.

## 5. Read paths

### 5.1 Node path (`EndpointKind::Node`) — loopback only

`GET {base}/s/<store_id>[:<root>]/<resource_key>`. A loopback node may answer with
verified PLAINTEXT or with CIPHERTEXT; the shape is detected DETERMINISTICALLY by
headers (never assumed):

- **Verified plaintext** — `2xx` AND `X-Dig-Verified: true` → the body is the
  node-decrypted, node-verified plaintext (loopback trust). Content type: the
  response `Content-Type`, else derived (§7). No client-side crypto.
- **Ciphertext** — `2xx` AND (`X-Dig-Encrypted: true` OR an `X-Dig-Inclusion-Proof`
  header) → the body is opaque ciphertext that MUST be client-side verified+decrypted
  exactly like the rpc path (§5.2 step 4), reusing `digstore-core` and threading the
  URN salt. The trust root is the URN's pinned root, else the (loopback) node's
  `X-Dig-Root`; the proof is `X-Dig-Inclusion-Proof`; `X-Dig-Chunk-Lens` (comma-
  separated) gives the chunk layout. A node returning ciphertext is NOT trusted blindly.
- `2xx` that is neither attested plaintext nor decryptable ciphertext → hard
  `VerifyFailed` (fail-closed; §6 `IntegrityFailure`). Bytes are never returned.
- `404` → hard `NotFound`.
- other non-2xx / transport failure → a transport failure (ladder falls through).

### 5.2 RPC path (`EndpointKind::Rpc`) — the trust root comes from the URN

1. The trust root MUST be the URN's pinned root. A ROOTLESS URN over this untrusted
   tier is REJECTED with a hard `RootRequired` error (its root would otherwise come
   from the same untrusted gateway, allowing a compromised gateway to prove attacker
   bytes for a public store against a fake root). No `dig.getAnchoredRoot` call is
   made on this tier.
2. `retrieval_key` per §3.
3. Stream windowed `dig.getContent {store_id, root, retrieval_key, offset, length} ->
   {total_length, offset, next_offset?, complete?, ciphertext (b64), inclusion_proof
   (b64), chunk_lens}`, accumulating ciphertext until `complete` or `next_offset ==
   null`. `total_length == 0` → hard `NotFound`.
4. **Verify then decrypt** (gate-then-decrypt), via `digstore-core`:
   - inclusion: `resource_leaf(ciphertext) == proof.leaf`, `proof.verify()`, and
     `proof.root == trusted_root`. ANY failure → integrity failure (§6).
   - decrypt: split by `chunk_lens` (empty ⇒ single chunk), AES-256-GCM-SIV-open each
     under the URN key. A tag failure → integrity failure (§6).
5. Content type derived per §7.

A JSON-RPC `error` object or a malformed/unexpected body is a hard `Rpc` error (the
endpoint IS reachable). A transport failure / non-2xx HTTP is a transport failure.

## 6. Outcomes (fail-closed)

A resolve yields `Result<ResolveOutcome, ResolveError>`:

- `ResolveOutcome::Success(data)` — verified content.
- `ResolveOutcome::IntegrityFailure` — bytes were fetched but failed inclusion or
  decrypt verification. The unverified bytes MUST NOT be returned or carried. This is
  returned IMMEDIATELY at the producing tier (never cascaded, never masked as
  unreachable).
- `ResolveOutcome::Unreachable` — every tier was transport-unreachable; nothing was
  fetched.
- `Err(ResolveError)` — `Parse`, `NotFound`, `RootRequired` (a rootless URN over the
  untrusted rpc tier), or `Rpc` (a reachable protocol error).

`IntegrityFailure` and `Unreachable` MUST be distinct and never conflated:
integrity-fail = reached the network, bytes don't verify (security); unreachable =
couldn't reach the network (retryable).

For a render/image path, `IntegrityFailure` MAY render a branded "Integrity
Verification Failed" `text/html` document and `Unreachable` a branded "DIG Network
unreachable" + Connect-to-Node document. An image/object-URL helper MUST NOT return
the unverified bytes as content for an integrity failure — it returns the security
document instead.

## 7. Content type

Derived from the resource path extension first, then a magic-byte sniff, falling back
to `application/octet-stream`. The node path prefers the response `Content-Type`.

## 8. Transport

The core logic depends only on an injected async transport (`HttpTransport`: `get`,
`post_json`). Bundled implementations: `reqwest` (native, `native` feature) and the
browser `fetch` (wasm, `wasm` feature). Node-class transports SHOULD use short
connect timeouts so dead ladder tiers fall through quickly.

## 9. wasm surface (`@dignetwork/dig-urn-resolver`)

The front-door API is the branded `DigNetwork` class:

- `new DigNetwork(endpoint?, connectUrl?, cachePath?)` — `cachePath` is an optional
  disk-cache directory (native; ignored in the browser, see §11).
- `dig.resolve(urn) : Promise<{ outcome, bytes, contentType }>`, `outcome ∈
  "success" | "integrity_failure" | "unreachable"`. `contentType` is present on
  EVERY result.
- `dig.resolveImageUrl(urn) : Promise<string>` — an `<img src>` URL that ALWAYS
  resolves (never throws for a normal failure): a `blob:` URL of the real verified
  image on success, else a branded DIG error IMAGE as a `data:image/png;base64` URI
  matching the failure (integrity / unreachable / not-found / invalid-URN / generic).
  An `<img>` cannot render the HTML error docs, so these prerendered PNGs are the
  image-path variant. FAIL-CLOSED: the integrity image is a STATIC branded
  placeholder — unverified bytes are NEVER returned as the image.

Low-level free functions `resolve(urn, endpoint?, connectUrl?)` and
`resolveObjectUrl(urn, endpoint?, connectUrl?)` MAY also be exported (delegating to
`DigNetwork`); the branded class is the documented surface.

## 10. Conformance

- URN parse + retrieval/decryption keys MUST match `digstore-core` byte-for-byte.
- A tampered ciphertext, a non-chaining proof, a wrong root, or a wrong/absent salt
  MUST yield `IntegrityFailure`, never data.
- Only an asserted-loopback host is granted node trust; a remote host (incl. an
  override) MUST use the verified rpc path. A node response without `X-Dig-Verified:
  true` MUST fail closed.
- A rootless URN over the rpc tier MUST be rejected (`RootRequired`); the rpc tier
  MUST NOT call `dig.getAnchoredRoot`.
- Node-absent + a serving rpc gateway MUST resolve a valid ROOT-PINNED resource to
  `Success`.
- A node CIPHERTEXT response MUST be client-side verified+decrypted (not trusted); a
  salted URN MUST decrypt salted content on BOTH tiers, and a wrong/absent salt MUST
  yield `IntegrityFailure`.
- Caching (§11) MUST NOT weaken fail-closed: only `Success` is cached; a disk hit is
  re-verified (a tampered file → `IntegrityFailure`).

## 11. Caching

Results are cached in front of resolve; this MUST NOT weaken fail-closed (§6).

- **Cacheable:** ONLY a verified `Success`. `IntegrityFailure` / `Unreachable` /
  `NotFound` / any `Err` MUST NOT be cached.
- **Key:** the content-addressed identity `storeId:root:resourceKey:salt` with the
  CONCRETE resolved root (a root-pinned URN's root, or the node's `X-Dig-Root`) —
  never the raw request URN. A rootless URN with no concrete root is not cached.
- **Memory tier (bounded LRU, both native + wasm):** process-trusted — holds only
  what THIS process verified this run; a hit MAY skip re-verification. Bounded by an
  entry count AND a byte budget (no unbounded growth in a wallet).
- **Disk tier (optional, native, UNTRUSTED):** stores the VERIFIABLE artifacts
  (ciphertext + inclusion proof + chunk lengths), NOT plaintext. A disk hit MUST be
  RE-VERIFIED against the URN's root before use (same merkle/decrypt gate); a tampered
  entry MUST fail verification → `IntegrityFailure` and MUST NOT be served. Filenames
  MUST be `SHA-256(identity)` (content-addressed, no path-traversal). Ignored where
  there is no filesystem (the browser); the memory tier still applies.
