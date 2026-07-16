# Branded error images

The `error-*.png` files are the branded, 512×512 DIG-brand placeholder images the
crate embeds (`src/images.rs` → `include_bytes!`) and returns from
`DigNetwork.resolveImageUrl` on a non-success outcome — as a `data:image/png;base64`
URI. A raster PNG renders deterministically in any `<img>` (some CSP policies block
`data:image/svg+xml`).

- `error-integrity.png` — verification failed (tampered / decoy). SECURITY, red.
- `error-unreachable.png` — no node/gateway reachable. Retryable, blue.
- `error-not-found.png` — the resource does not exist.
- `error-invalid-urn.png` — bad URN, or a rootless URN over the gateway.
- `error-generic.png` — any other failure.

## Provenance / regenerating

The `.svg` files are the DESIGN SOURCE, emitted from the single source of truth
`dig_urn_resolver::images::svg`. Rendering happens ONCE at authoring — there is NO
runtime SVG-raster dependency. To regenerate:

```sh
cargo run --example render_error_images
for f in assets/error-*.svg; do resvg --width 512 --height 512 "$f" "${f%.svg}.png"; done
```

Then commit both the `.svg` and `.png` files.
