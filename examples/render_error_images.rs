//! Authoring tool (run ONCE, then commit): emit the branded error SVGs into
//! `assets/` from the crate's `images::svg` source of truth. After running this,
//! rasterize each to a 512×512 PNG (committed alongside; the crate embeds the PNGs):
//!
//! ```sh
//! cargo run --example render_error_images
//! for f in assets/error-*.svg; do resvg "$f" "${f%.svg}.png"; done
//! ```
//!
//! Rendering happens ONCE at authoring — there is NO runtime SVG-raster dependency.

use dig_urn_resolver::images::{svg, ErrorImage};
use std::fs;

fn main() {
    fs::create_dir_all("assets").expect("create assets/");
    for (kind, slug) in [
        (ErrorImage::Integrity, "integrity"),
        (ErrorImage::Unreachable, "unreachable"),
        (ErrorImage::NotFound, "not-found"),
        (ErrorImage::InvalidUrn, "invalid-urn"),
        (ErrorImage::Generic, "generic"),
    ] {
        let path = format!("assets/error-{slug}.svg");
        fs::write(&path, svg(kind)).expect("write svg");
        println!("wrote {path}");
    }
    println!(
        "Now rasterize: for f in assets/error-*.svg; do resvg \"$f\" \"${{f%.svg}}.png\"; done"
    );
}
