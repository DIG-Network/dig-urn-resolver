#!/usr/bin/env node
// Build the DUAL-TARGET @dignetwork/dig-urn-resolver npm package: one package that
// imports cleanly in BOTH a browser bundler (Vite/webpack) AND a Node.js service.
//
// wasm-pack emits per-target glue, so we build the `web` target and the `nodejs`
// target and assemble a single package whose `exports` map routes each environment
// to the right entry (mirrors digstore's dual-target pkg). The Rust/wasm CORE is
// identical across both; only the wasm-bindgen loader glue differs.
//
//   node scripts/build-npm.mjs   → ./pkg  (ready to `npm publish ./pkg`)
//
// Requires: wasm-pack + the wasm32-unknown-unknown target on PATH.

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";

const CRATE = process.cwd();
const OUT = `${CRATE}/pkg`;
const WASM_ARGS = ["--no-default-features", "--features", "wasm"];

function wasmPack(target, outDir) {
  execFileSync(
    "wasm-pack",
    ["build", "--target", target, "--out-dir", outDir, "--out-name", "dig_urn_resolver", "--", ...WASM_ARGS],
    { stdio: "inherit", cwd: CRATE },
  );
}

// 1) Build both targets into scratch dirs.
rmSync(OUT, { recursive: true, force: true });
rmSync(`${CRATE}/pkg-web`, { recursive: true, force: true });
rmSync(`${CRATE}/pkg-node`, { recursive: true, force: true });
wasmPack("web", "pkg-web");
wasmPack("nodejs", "pkg-node");

// 2) Assemble ./pkg = { web/, node/ } + a dual-export package.json.
mkdirSync(`${OUT}/web`, { recursive: true });
mkdirSync(`${OUT}/node`, { recursive: true });
for (const f of ["dig_urn_resolver.js", "dig_urn_resolver.d.ts", "dig_urn_resolver_bg.wasm"]) {
  cpSync(`${CRATE}/pkg-web/${f}`, `${OUT}/web/${f}`);
}
// The `web` target also ships the wasm's own .d.ts and a bg.js binding.
if (existsSync(`${CRATE}/pkg-web/dig_urn_resolver_bg.wasm.d.ts`)) {
  cpSync(`${CRATE}/pkg-web/dig_urn_resolver_bg.wasm.d.ts`, `${OUT}/web/dig_urn_resolver_bg.wasm.d.ts`);
}
if (existsSync(`${CRATE}/pkg-web/dig_urn_resolver_bg.js`)) {
  cpSync(`${CRATE}/pkg-web/dig_urn_resolver_bg.js`, `${OUT}/web/dig_urn_resolver_bg.js`);
}
for (const f of ["dig_urn_resolver.js", "dig_urn_resolver.d.ts", "dig_urn_resolver_bg.wasm"]) {
  cpSync(`${CRATE}/pkg-node/${f}`, `${OUT}/node/${f}`);
}
if (existsSync(`${CRATE}/pkg-node/dig_urn_resolver_bg.wasm.d.ts`)) {
  cpSync(`${CRATE}/pkg-node/dig_urn_resolver_bg.wasm.d.ts`, `${OUT}/node/dig_urn_resolver_bg.wasm.d.ts`);
}

const version = JSON.parse(readFileSync(`${CRATE}/pkg-web/package.json`, "utf8")).version;

// Per-target package.json so Node loads the right module system for each subdir:
// the `web` target is ESM, the `nodejs` target is CommonJS. The nearest package.json
// `type` governs, so mixing them in one package is clean + standard.
writeFileSync(`${OUT}/web/package.json`, JSON.stringify({ type: "module" }, null, 2) + "\n");
writeFileSync(`${OUT}/node/package.json`, JSON.stringify({ type: "commonjs" }, null, 2) + "\n");

const pkg = {
  name: "@dignetwork/dig-urn-resolver",
  version,
  description:
    "Resolve a DIG URN to its data through the protocol (node-first ladder, verified + decrypted). Works in the browser AND Node.js.",
  license: "GPL-2.0-only",
  repository: { type: "git", url: "https://github.com/DIG-Network/dig-urn-resolver" },
  keywords: ["dig", "chia", "urn", "resolver", "wasm", "nft"],
  // Route each environment to its wasm-bindgen glue; the API is identical. `browser`
  // + `import` → the ESM web build; `node`/`require` → the CommonJS Node build.
  types: "./web/dig_urn_resolver.d.ts",
  module: "./web/dig_urn_resolver.js",
  main: "./node/dig_urn_resolver.js",
  browser: "./web/dig_urn_resolver.js",
  exports: {
    ".": {
      types: "./web/dig_urn_resolver.d.ts",
      browser: "./web/dig_urn_resolver.js",
      import: "./web/dig_urn_resolver.js",
      require: "./node/dig_urn_resolver.js",
      node: "./node/dig_urn_resolver.js",
      default: "./web/dig_urn_resolver.js",
    },
  },
  files: ["web", "node", "README.md", "LICENSE"],
  sideEffects: ["./web/dig_urn_resolver.js", "./node/dig_urn_resolver.js"],
};
writeFileSync(`${OUT}/package.json`, JSON.stringify(pkg, null, 2) + "\n");

for (const f of ["README.md", "LICENSE"]) {
  if (existsSync(`${CRATE}/${f}`)) cpSync(`${CRATE}/${f}`, `${OUT}/${f}`);
}

// 3) Clean scratch.
rmSync(`${CRATE}/pkg-web`, { recursive: true, force: true });
rmSync(`${CRATE}/pkg-node`, { recursive: true, force: true });

console.log(`Assembled dual-target @dignetwork/dig-urn-resolver@${version} at ./pkg (web + node).`);
