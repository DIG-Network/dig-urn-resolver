//! Branded error IMAGES for the `<img src>` path ([`crate::wasm::DigNetwork::resolve_image_url`]).
//!
//! An `<img>` tag cannot render the HTML error documents in [`crate::pages`] (it
//! would show a broken-image icon), so the image path degrades to a branded, square
//! **SVG** per failure — icon + short label + `DIG NETWORK` wordmark, in the DIG
//! dark brand. Each is a static `const`-built string embedded in the crate and
//! returned as a `data:image/svg+xml;base64,…` URI: NO external fetch (CSP-safe,
//! offline-safe), and — critically — for an integrity failure the image is a STATIC
//! placeholder, so no tampered/unverified byte can ever become the `<img>` content.
//!
//! The SVGs are intentional (icon + label + wordmark), legible when scaled down to a
//! typical NFT thumbnail, and reuse the same palette as [`crate::pages`].

use crate::error::ResolveError;
use crate::resolver::ResolveOutcome;
use base64::Engine;

/// The DIG brand font stack (system fonts — no external font fetch).
const FONT: &str = "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif";

/// Which branded error image to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorImage {
    /// Served bytes failed verification (tampered / decoy). Red security treatment.
    Integrity,
    /// No node + gateway reachable. Blue, retryable, with a connect-a-node hint.
    Unreachable,
    /// The resource does not exist.
    NotFound,
    /// The input was not a resolvable DIG URN (bad URN, or rootless over the gateway).
    InvalidUrn,
    /// Any other failure.
    Generic,
}

/// The branded image for a non-success [`ResolveOutcome`] (only ever called for a
/// non-success variant).
pub fn for_outcome(outcome: &ResolveOutcome) -> ErrorImage {
    match outcome {
        ResolveOutcome::Success(_) => ErrorImage::Generic, // never used for Success
        ResolveOutcome::IntegrityFailure => ErrorImage::Integrity,
        ResolveOutcome::Unreachable => ErrorImage::Unreachable,
    }
}

/// The branded image for a hard [`ResolveError`].
pub fn for_error(err: &ResolveError) -> ErrorImage {
    match err {
        ResolveError::Parse(_) | ResolveError::RootRequired => ErrorImage::InvalidUrn,
        ResolveError::NotFound => ErrorImage::NotFound,
        // Transport never escapes `resolve` (it becomes `Unreachable`), but map it
        // sensibly for completeness.
        ResolveError::Transport(_) => ErrorImage::Unreachable,
        ResolveError::VerifyFailed(_) | ResolveError::DecryptFailed => ErrorImage::Integrity,
        ResolveError::Rpc(_) => ErrorImage::Generic,
    }
}

/// Per-image treatment: accent colour, background glow, the icon glyph symbol, the
/// title, and an optional subtitle.
fn treatment(
    kind: ErrorImage,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match kind {
        // (accent, glow, glyph, title, subtitle)
        ErrorImage::Integrity => (
            "#e5484d",
            "#3a1416",
            "!",
            "Verification failed",
            "Content could not be trusted",
        ),
        ErrorImage::Unreachable => (
            "#3b6cf6",
            "#14213a",
            "\u{21bb}",
            "Network unreachable",
            "Connect a DIG node",
        ),
        ErrorImage::NotFound => ("#7f8db3", "#141a2e", "?", "Content not found", ""),
        ErrorImage::InvalidUrn => ("#7f8db3", "#141a2e", "!", "Invalid DIG URN", ""),
        ErrorImage::Generic => ("#7f8db3", "#141a2e", "!", "Something went wrong", ""),
    }
}

/// The PRERENDERED PNG bytes for an error image (512×512), embedded at build time.
///
/// These are rasterized ONCE at authoring from [`svg`] (via `resvg`, see
/// `examples/render_error_images.rs`) and committed under `assets/` — there is NO
/// runtime SVG-raster dependency, and a raster PNG renders deterministically in any
/// `<img>` (some CSP policies block `data:image/svg+xml`). Each is a STATIC
/// placeholder per failure kind, so it can never carry tampered/unverified content.
pub fn png(kind: ErrorImage) -> &'static [u8] {
    match kind {
        ErrorImage::Integrity => include_bytes!("../assets/error-integrity.png"),
        ErrorImage::Unreachable => include_bytes!("../assets/error-unreachable.png"),
        ErrorImage::NotFound => include_bytes!("../assets/error-not-found.png"),
        ErrorImage::InvalidUrn => include_bytes!("../assets/error-invalid-urn.png"),
        ErrorImage::Generic => include_bytes!("../assets/error-generic.png"),
    }
}

/// The branded image as a `data:image/png;base64,…` URI, ready for an `<img src>`.
pub fn data_uri(kind: ErrorImage) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(png(kind));
    format!("data:image/png;base64,{b64}")
}

/// Render the branded, square SVG for a given error image (viewBox 512×512) — the
/// DESIGN SOURCE the committed PNGs are rasterized from (see [`png`]).
pub fn svg(kind: ErrorImage) -> String {
    let (accent, glow, glyph, title, subtitle) = treatment(kind);
    let subtitle_el = if subtitle.is_empty() {
        String::new()
    } else {
        format!(
            "<text x='256' y='372' text-anchor='middle' font-family='{FONT}' font-size='26' fill='#aeb7d4'>{subtitle}</text>"
        )
    };
    format!(
        r##"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512' width='512' height='512' role='img' aria-label='DIG Network: {title}'>
  <defs><radialGradient id='bg' cx='50%' cy='0%' r='120%'>
    <stop offset='0%' stop-color='{glow}'/><stop offset='60%' stop-color='#0a0f1e'/><stop offset='100%' stop-color='#070a14'/>
  </radialGradient></defs>
  <rect width='512' height='512' fill='url(#bg)'/>
  <circle cx='256' cy='190' r='68' fill='none' stroke='{accent}' stroke-width='8'/>
  <text x='256' y='226' text-anchor='middle' font-family='{FONT}' font-size='84' font-weight='700' fill='{accent}'>{glyph}</text>
  <text x='256' y='320' text-anchor='middle' font-family='{FONT}' font-size='40' font-weight='700' fill='#ffffff'>{title}</text>
  {subtitle_el}
  <text x='256' y='452' text-anchor='middle' font-family='{FONT}' font-size='22' font-weight='700' letter-spacing='6' fill='{accent}'>DIG NETWORK</text>
  <text x='256' y='478' text-anchor='middle' font-family='{FONT}' font-size='16' letter-spacing='2' fill='#7f8db3'>dig.net</text>
</svg>"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    #[test]
    fn every_kind_embeds_a_png_data_uri() {
        for kind in [
            ErrorImage::Integrity,
            ErrorImage::Unreachable,
            ErrorImage::NotFound,
            ErrorImage::InvalidUrn,
            ErrorImage::Generic,
        ] {
            // The embedded bytes are real PNGs (magic bytes).
            assert!(png(kind).starts_with(PNG_MAGIC), "PNG magic present");
            let uri = data_uri(kind);
            assert!(uri.starts_with("data:image/png;base64,"));
            // The decoded payload round-trips back to the PNG bytes.
            let b64 = uri.trim_start_matches("data:image/png;base64,");
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            assert!(decoded.starts_with(PNG_MAGIC));
        }
    }

    #[test]
    fn svg_design_source_is_labelled_and_square() {
        for kind in [
            ErrorImage::Integrity,
            ErrorImage::Unreachable,
            ErrorImage::NotFound,
            ErrorImage::InvalidUrn,
            ErrorImage::Generic,
        ] {
            let svg = svg(kind);
            assert!(svg.starts_with("<svg"));
            assert!(svg.contains("DIG NETWORK"), "wordmark present");
            assert!(svg.contains("viewBox='0 0 512 512'"), "square + scalable");
        }
    }

    #[test]
    fn labels_match_outcome() {
        assert!(svg(ErrorImage::Integrity).contains("Verification failed"));
        assert!(svg(ErrorImage::Unreachable).contains("Network unreachable"));
        assert!(svg(ErrorImage::Unreachable).contains("Connect a DIG node"));
        assert!(svg(ErrorImage::NotFound).contains("Content not found"));
        assert!(svg(ErrorImage::InvalidUrn).contains("Invalid DIG URN"));
        assert!(svg(ErrorImage::Generic).contains("Something went wrong"));
    }

    #[test]
    fn outcome_and_error_mapping() {
        assert_eq!(
            for_outcome(&ResolveOutcome::IntegrityFailure),
            ErrorImage::Integrity
        );
        assert_eq!(
            for_outcome(&ResolveOutcome::Unreachable),
            ErrorImage::Unreachable
        );
        assert_eq!(for_error(&ResolveError::NotFound), ErrorImage::NotFound);
        assert_eq!(
            for_error(&ResolveError::Parse("x".into())),
            ErrorImage::InvalidUrn
        );
        assert_eq!(
            for_error(&ResolveError::RootRequired),
            ErrorImage::InvalidUrn
        );
        assert_eq!(
            for_error(&ResolveError::Rpc("x".into())),
            ErrorImage::Generic
        );
        assert_eq!(
            for_error(&ResolveError::DecryptFailed),
            ErrorImage::Integrity
        );
    }

    #[test]
    fn integrity_image_is_static_never_carries_bytes() {
        // The integrity image is a constant embedded PNG — it can NEVER contain any
        // (tampered) resource bytes, so no unverified byte reaches the <img>.
        let uri = data_uri(ErrorImage::Integrity);
        assert!(!uri.contains("TAMPERED_SECRET_PAYLOAD"));
        // Identical regardless of any surrounding context — it is a pure constant.
        assert_eq!(uri, data_uri(ErrorImage::Integrity));
        assert_eq!(png(ErrorImage::Integrity), png(ErrorImage::Integrity));
    }
}
