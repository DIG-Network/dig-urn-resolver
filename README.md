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

const dig = new DigNetwork();               // or: new DigNetwork(endpoint, connectUrl)

// The NFT-image case — a blob: URL for <img src>, working with no dig-node running:
img.src = await dig.resolveImageUrl(nftDataUri);

// Or the typed form:
const { outcome, bytes, contentType } = await dig.resolve(nftDataUri);
// outcome ∈ "success" | "integrity_failure" | "unreachable"
```

On an integrity failure, `resolveImageUrl` returns the branded security page —
**never** the unverified bytes as an image. Low-level free functions (`resolve`,
`resolveObjectUrl`) remain available for callers that prefer them.

### CORS note for consuming apps (Sage/Tauri)

The `/health` + `/s/` probes hit `dig.local`/`localhost` from the app origin and may
be CORS-blocked in a desktop webview; the `rpc.dig.net` fallback (`Access-Control-
Allow-Origin: *`) always works, so a resolve succeeds node-absent. Add the endpoints
to the app's `connect-src` CSP.

## Example

```
cargo run --example sage_nft_image
```

Resolves a root-pinned NFT-image URN to displayable bytes with no dig-node running
(rpc fallback), the exact byte path `resolveObjectUrl` wraps for `<img src>`.

## License

GPL-2.0-only (inherited from the reused `digstore-core` read-crypto).
