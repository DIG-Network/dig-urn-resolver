# dig-urn-resolver

Resolve a DIG URN to its data through the protocol, **node-first**. A Rust crate and
a `@dignetwork/dig-urn-resolver` wasm/npm package. First consumer: **Sage wallet NFT
images**.

Given a URN of the form

```
urn:dig:chia:<store_id>[:<root>]/<resource_key>[?salt=<hex>]
```

it returns the resource's bytes + content type, following the canonical §5.3 ladder
— **explicit override > `dig.local` > `localhost:9778` > `rpc.dig.net`** — using the
first tier that responds:

- **node tier** — `GET /s/<storeId>[:<root>]/<path>`: a local dig-node decrypts +
  verifies server-side under a loopback trust boundary and returns plaintext.
- **rpc tier** — `dig.getAnchoredRoot` + `dig.getContent`: a *blind* fetch of opaque
  ciphertext + inclusion proofs from the public gateway, verified against the
  chain-anchored root and decrypted **client-side** (fail-closed).

All read-crypto (URN canonicalization + retrieval-key derivation, merkle inclusion
verify, AES-256-GCM-SIV open) is reused verbatim from `digstore-core` — the same
functions the browser read-crypto and the on-chain crates share — so this crate can
never skew from the canonical crypto.

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

```js
import init, { resolve, resolveObjectUrl } from "@dignetwork/dig-urn-resolver";
await init();

// The NFT-image case — a blob: URL for <img src>, working with no dig-node running:
img.src = await resolveObjectUrl(nftDataUri);

// Or the typed form:
const { outcome, bytes, contentType } = await resolve(nftDataUri);
// outcome ∈ "success" | "integrity_failure" | "unreachable"
```

On an integrity failure, `resolveObjectUrl` returns the security page — **never** the
unverified bytes as an image.

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
