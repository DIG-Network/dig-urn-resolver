# dig-urn-resolver

Resolve a DIG URN to its data through the protocol, **node-first**. A Rust crate and
a `@dignetwork/dig-urn-resolver` wasm/npm package. First consumer: **Sage wallet NFT
images**.

## Positioning — the canonical client-side URN resolver

This is **THE** canonical, project-wide client-side URN→data resolver (the #668
convergence: hub, the extension, dig-sdk, dig-dns and other consumers converge on
it). It sits strictly **upstream of dig-node**: it is a *client* that talks to a
dig-node over the wire (the node `/s/` + `/health` surface, else the `rpc.dig.net`
gateway) — dig-node does all the heavy lifting (store sync, serve, decrypt, chain
anchoring) and **never depends on this crate**. Consume it from Rust (`dig-urn-resolver`)
or JS/wasm (`@dignetwork/dig-urn-resolver`); do not reimplement URN resolution
elsewhere.

Given a URN of the form

```
urn:dig:chia:<store_id>[:<root>]/<resource_key>[?salt=<hex>]
```

it returns the resource's bytes + content type, following the canonical §5.3 ladder
— **explicit override > `dig.local` > `localhost:9778` > `rpc.dig.net`** — using the
first tier that responds:

- **node tier** — `GET /s/<storeId>[:<root>]/<path>`: a local dig-node decrypts +
  verifies server-side under a loopback trust boundary and returns plaintext.
- **rpc tier** — `dig.getContent`: a *blind* fetch of opaque ciphertext + inclusion
  proofs from the untrusted public gateway, verified against the chain-anchored root
  and decrypted **client-side** (fail-closed).

All read-crypto (URN canonicalization + retrieval-key derivation, merkle inclusion
verify, AES-256-GCM-SIV open) is reused verbatim from `digstore-core` — the same
functions the browser read-crypto and the on-chain crates share — so this crate can
never skew from the canonical crypto.

## Security invariants

- **Node trust is loopback-only.** The crypto-free node `/s/` path is trusted ONLY
  for an asserted-loopback host (`127.0.0.0/8` / `::1` / `localhost`, or `dig.local`
  iff it resolves to loopback) — it is the user's own machine. ANY other host,
  including an explicit override pointed at a remote host, uses the client-VERIFIED
  rpc path. On the node path the response MUST carry `X-Dig-Verified: true`, else the
  bytes are rejected fail-closed. (Defeats a remote/override host and a LAN mDNS
  spoof of `.local` serving unverified bytes as trusted.)
- **The rpc trust root comes from the URN, not the gateway.** Over the untrusted
  gateway only a **root-pinned** URN is accepted; a rootless URN is rejected
  (`RootRequired`) because its root would otherwise come from the same gateway
  serving the content. (Rootless is fine over a loopback node — the local node is the
  trust anchor. Root-pinned + private/salted stores are unaffected.)

## Three outcomes, never conflated

| Outcome | Meaning | Bytes |
|---|---|---|
| `Success` | verified, decrypted content | the real content |
| `IntegrityFailure` | bytes fetched but failed merkle/decrypt verify (tampered / decoy / wrong root) — a hard, fail-**closed** security failure | never the unverified bytes; renders a branded "Integrity Verification Failed" page |
| `Unreachable` | every tier down; nothing fetched — friendly + retryable | a branded "DIG Network unreachable" + Connect-to-Node page |

A malformed URN, a not-found resource, and a reachable rpc protocol error are hard
errors (`ResolveError`).

## Rust

```rust
use dig_urn_resolver::{native, ResolveOutcome};

#[tokio::main]
async fn main() {
    match native::resolve("urn:dig:chia:<store>:<root>/img/logo.png").await.unwrap() {
        ResolveOutcome::Success(data) => { /* data.bytes, data.content_type */ }
        ResolveOutcome::IntegrityFailure => { /* security failure — do not show */ }
        ResolveOutcome::Unreachable => { /* network down — offer "connect a node" */ }
    }
}
```

Inject a custom transport (or an explicit endpoint) via `Resolver::with_options`.

## Browser / Sage (`@dignetwork/dig-urn-resolver`)

The front-door API is the branded, well-typed **`DigNetwork`** client:

```js
import init, { DigNetwork } from "@dignetwork/dig-urn-resolver";
await init();

const dig = new DigNetwork();        // or: new DigNetwork(endpoint, connectUrl, cachePath)

// The NFT-image case — a URL for <img src>, working with no dig-node running:
img.src = await dig.resolveImageUrl(nftDataUri);

// Or the typed form (real outcome + MIME, not an image):
const { outcome, bytes, contentType } = await dig.resolve(nftDataUri);
// outcome ∈ "success" | "integrity_failure" | "unreachable"
```

`resolveImageUrl` ALWAYS returns a usable `<img>` URL and never throws for a normal
failure: the real verified image on success, else a **branded DIG error image**
(embedded PNG `data:` URI) matching the failure — integrity failure, network
unreachable, not found, invalid URN, or a generic error. On an integrity failure it
is the STATIC branded placeholder — **never** the unverified bytes as the image. (The
HTML error pages via `resolve().render()` stay for the webview/navigation case.)
Low-level free functions (`resolve`, `resolveObjectUrl`) remain available.

## Caching

URNs are content-addressed → immutable → cacheable, so results are cached as an
additive layer in front of resolve that never weakens fail-closed:

- **Only VERIFIED `Success` bytes are cached** — never an integrity/unreachable/
  not-found failure (a cached failure would block recovery).
- **Keyed by the content-addressed identity** `storeId:root:resourceKey:salt` with
  the CONCRETE resolved root — a root-pinned URN is immutable; a rootless URN is
  cached under the root the resolve produced (`X-Dig-Root`), never a stale
  URN→bytes mapping.
- **Memory (default, bounded LRU):** process-trusted (only holds what this process
  verified this run) — a hit skips re-verification.
- **Disk (optional `cachePath`; native Rust AND Node.js):** UNTRUSTED — it stores the
  *verifiable artifacts* (ciphertext + proof + chunk lengths), and a disk hit is
  **re-verified** against the URN's root before use, so a tampered on-disk file FAILS
  verification → `IntegrityFailure` (never served). Filenames are `SHA-256(identity)`
  (no path-traversal). Ignored clientside in the browser (no filesystem); the memory
  cache still applies there.

Persistent disk caching is a **native (Rust) capability** — pass a `cache_path` in
`ResolveOptions`, and verified results survive across process runs (a long-lived
on-disk cache under the given directory). Because URNs are immutable + content-
addressed, a later run re-serves a cached asset without a network round-trip, and
every disk hit is still re-verified against the URN's root before use:

```rust
use dig_urn_resolver::{native, ResolveOptions, ResolveOutcome};

#[tokio::main]
async fn main() {
    let options = ResolveOptions {
        cache_path: Some("/var/cache/dig-urn".into()), // long-lived disk cache
        ..Default::default()
    };
    match native::resolve_with("urn:dig:chia:<store>:<root>/img/logo.png", options)
        .await
        .unwrap()
    {
        ResolveOutcome::Success(data) => { /* served from disk on a later run */ }
        ResolveOutcome::IntegrityFailure => { /* re-verify failed — never served */ }
        ResolveOutcome::Unreachable => { /* network down — offer "connect a node" */ }
    }
}
```

In the `@dignetwork/dig-urn-resolver` wasm package the `DigNetwork` constructor takes
the same `cachePath` as its third argument, and it is **fully functional under
Node.js** — the Node build injects Node's `fs`, so verified results persist to the
given directory and are re-verified on read, exactly like the native crate:

```js
// Node.js service (CommonJS) — a persistent, cross-run disk cache
const { DigNetwork } = require("@dignetwork/dig-urn-resolver");

//                         endpoint  connectUrl  cachePath
const dig = new DigNetwork(undefined, undefined, "/var/cache/dig-urn");

// First run fetches + verifies; a later run (same cachePath) re-serves from disk.
const img = await dig.resolveImageUrl("urn:dig:chia:<store>:<root>/img/logo.png");
```

**Clientside (browser) `cachePath` is a harmless no-op** — a browser has no
filesystem, so the wasm build never wires `fs` there and the bounded in-memory cache
applies instead (a same-process hit still skips re-verification). The persistent disk
cache is available to native Rust consumers AND to the Node.js build; only the browser
falls back to memory-only.

## Runs in the browser AND Node.js

The `@dignetwork/dig-urn-resolver` package is **dual-target** — one package that
imports cleanly in both:

```js
// Browser bundler (Vite / webpack) — ESM
import init, { DigNetwork } from "@dignetwork/dig-urn-resolver";
await init();

// Node.js service — CommonJS
const { DigNetwork } = require("@dignetwork/dig-urn-resolver");
```

The branded `DigNetwork` API, the three fail-closed outcomes, and the MIME are
IDENTICAL in both; only env-specific plumbing differs, and it degrades gracefully —
never a hard-fail in either environment:

- **Ladder** — the `dig.local`/`localhost` `/health` probe works in Node; in a
  browser it's often CORS-blocked. The probe is caught/timed-out, so the ladder
  simply falls through to the verified `rpc.dig.net` tier (never to unverified bytes).
- **Cache** — the disk `cachePath` works natively AND under Node.js (the Node build
  injects `fs`); in a browser there is no filesystem, so `cachePath` is a harmless
  no-op and the bounded in-memory cache applies.
- **Image URL** — `resolveImageUrl` returns a `blob:` URL where `URL.createObjectURL`
  exists (browser) and a `data:` URL otherwise (Node.js) — always usable, never throws.

## Content type & the default view

`contentType` is present on every `resolve` result: the store's stored
`Content-Type` on the node path, else inferred from the URN path extension / magic
bytes. A bare-store or trailing-slash URN resolves to the §8.5 default view
`index.html`.

### CORS note for consuming apps (Sage/Tauri)

The `/health` + `/s/` probes hit `dig.local`/`localhost` from the app origin and may
be CORS-blocked in a desktop webview; the `rpc.dig.net` fallback (`Access-Control-
Allow-Origin: *`) always works, so a resolve succeeds node-absent. Add the endpoints
to the app's `connect-src` CSP. For the browser node path to read the verification
attestation, the node must send `Access-Control-Expose-Headers: X-Dig-Verified`
(a missing header fails closed) — see #669.

## Example

```
cargo run --example sage_nft_image
```

Resolves a root-pinned NFT-image URN to displayable bytes with no dig-node running
(rpc fallback), the exact byte path `resolveObjectUrl` wraps for `<img src>`.

## License

GPL-2.0-only (inherited from the reused `digstore-core` read-crypto).
