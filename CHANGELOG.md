# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-20

### Changed
- Consume `dig-urn-protocol` (crates.io `0.1`) as the canonical `urn:dig:` parser and
  verification contract, retiring digstore-core's parallel URN parse (kills a two-parser
  drift). digstore-core is kept ONLY as the crypto-primitive backing (merkle codec/fold +
  symmetric read-crypto), reused byte-identically via `ContentCrypto`. The resolver's
  wire/lookup key maps to `DigUrn::content_key` (root-independent), NOT `retrieval_key`
  (root-pinned) — pinned by a new frozen-corpus cross-parser equivalence test. No wire
  change; reads are byte-identical.

## [0.3.1] - 2026-07-16

### CI
- Publish dig-urn-resolver to crates.io + depend on digstore-core 0.13.4 (#6)

## [0.3.0] - 2026-07-16

### Features
- DigNetwork constructor takes an options object, not positional args (#5)

## [0.2.0] - 2026-07-16

### Features
- Functional cachePath disk cache under Node.js (+ README examples) (#4)

## [0.1.2] - 2026-07-16

### CI
- **publish-npm:** Run the OIDC publish on node 22 (#3)

## [0.1.1] - 2026-07-16

### CI
- **publish-npm:** Publish via npm OIDC trusted publishing + auto-publish on tag (#2)

## [0.1.0] - 2026-07-16

### Features
- Dig-urn-resolver — URN→data resolver (crate + wasm + Sage example) (#1)


