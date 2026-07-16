# Runbook — dig-urn-resolver

## Local development

Prereqs: a stable Rust toolchain, the `wasm32-unknown-unknown` target, and
`wasm-pack` (for the npm package).

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack   # or the official installer

# Native build + tests + lint
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --features native -- -D warnings

# Coverage (must stay >= 80% lines)
cargo llvm-cov --features native \
  --ignore-filename-regex '(native|wasm)\.rs$' --fail-under-lines 80

# The Sage NFT-image demo (offline, rpc-fallback)
cargo run --example sage_nft_image

# Wasm / npm package — DUAL target (browser ESM + Node CommonJS)
node scripts/build-npm.mjs
# → ./pkg (@dignetwork/dig-urn-resolver): web/ (ESM) + node/ (CJS), exports-routed.
# Requires wasm-pack + the wasm32-unknown-unknown target + Node on PATH.
```

## Release + publish

Tag-driven, per-merge (a `modules/crates` repo — CLAUDE.md §3.6 model B):

1. Bump the version in `Cargo.toml` on the feature branch (SemVer; §2.4). Open a PR;
   the required gates (fmt, clippy, tests, coverage, commitlint, version-increment,
   wasm build) must be green.
2. On merge to `main`, `release.yml` regenerates `CHANGELOG.md` (git-cliff), commits
   it, tags `vX.Y.Z`, and pushes the tag with `RELEASE_TOKEN`. The GitHub Release
   triggers `publish-npm.yml`.
3. `publish-npm.yml` assembles the dual-target package (`scripts/build-npm.mjs` — web
   ESM + node CJS) and `npm publish`es `@dignetwork/dig-urn-resolver` using the org
   `NPM_TOKEN`. The package imports cleanly in both a browser bundler and Node.js.

### Secrets

- `RELEASE_TOKEN` — classic PAT that pushes the changelog commit + tag (a
  `GITHUB_TOKEN`-pushed tag would not trigger downstream workflows). Set on the repo.
- `NPM_TOKEN` — org-level npm publish token (public package).

Never print or commit either secret.

## Verify a publish

```sh
npm view @dignetwork/dig-urn-resolver version   # should be the new vX.Y.Z
```

## The digstore-core git dependency

The read-crypto is a git dependency on `DIG-Network/digstore` pinned to a specific
`rev` (see `Cargo.toml`), `default-features = false` (wasm-clean, no BLS/getrandom).
To adopt a newer digstore read-crypto, bump the `rev` and re-run the gates; the URN
parse + key derivation MUST stay byte-identical (a conformance property in `SPEC.md`).
