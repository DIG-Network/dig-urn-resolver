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
- `resource_key` — the path within the store. REQUIRED for a resolve (a bare store
  URN with no `/path` is rejected). An empty key resolves to `index.html` (§8.5).
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

`GET {base}/s/<store_id>[:<root>]/<resource_key>`.

- `2xx` AND the response carries `X-Dig-Verified: true` → the body is the decrypted,
  node-verified plaintext (loopback trust). The content type is the response
  `Content-Type` header, else derived (§7).
- `2xx` WITHOUT `X-Dig-Verified: true` → the node did not attest verification → hard
  `VerifyFailed` (fail-closed; §6 `IntegrityFailure`). The bytes are never returned.
- `404` → hard `NotFound`.
- other non-2xx / transport failure → treated as a transport failure (ladder falls
  through). No client-side crypto is performed on this path (trust is the loopback
  boundary + the attestation header).

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

- `new DigNetwork(endpoint?, connectUrl?)`.
- `dig.resolve(urn) : Promise<{ outcome, bytes, contentType }>`, `outcome ∈
  "success" | "integrity_failure" | "unreachable"`.
- `dig.resolveImageUrl(urn) : Promise<string>` — a `blob:` object URL for `<img
  src>`; the security/unreachable page for a non-success outcome, NEVER unverified
  bytes.

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
