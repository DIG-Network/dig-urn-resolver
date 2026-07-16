//! Deriving a resource's MIME type — from its path extension, with a magic-byte
//! sniff as a fallback for extensionless resources.
//!
//! The node transport prefers the response `Content-Type` header (the node already
//! knows the type); this module is the rpc-path derivation and the fallback.

/// The generic fallback when neither the extension nor the magic bytes identify a
/// type. Chosen so a browser downloads rather than mis-renders unknown data.
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Map a resource path's extension to a MIME type, or `None` when unknown.
fn from_extension(resource_key: &str) -> Option<&'static str> {
    let ext = resource_key.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" => "application/json",
        "txt" => "text/plain",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        _ => return None,
    })
}

/// Sniff a MIME type from the leading magic bytes, or `None` when unrecognized.
fn from_magic_bytes(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("image/png"),
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("image/webp"),
        [b'%', b'P', b'D', b'F', ..] => Some("application/pdf"),
        [0x00, 0x61, 0x73, 0x6D, ..] => Some("application/wasm"),
        _ => None,
    }
}

/// Derive the content type for a resource, extension first then a magic-byte sniff,
/// falling back to [`DEFAULT_CONTENT_TYPE`].
pub fn derive(resource_key: &str, bytes: &[u8]) -> String {
    from_extension(resource_key)
        .or_else(|| from_magic_bytes(bytes))
        .unwrap_or(DEFAULT_CONTENT_TYPE)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_wins_over_bytes() {
        assert_eq!(derive("photo.JPG", b"whatever"), "image/jpeg");
        assert_eq!(derive("index.html", &[]), "text/html");
        assert_eq!(derive("data.json", &[]), "application/json");
    }

    #[test]
    fn sniffs_when_extension_unknown() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert_eq!(derive("blob", &png), "image/png");
        assert_eq!(derive("blob", &[0xFF, 0xD8, 0xFF, 0x00]), "image/jpeg");
        let webp = *b"RIFF\0\0\0\0WEBP";
        assert_eq!(derive("blob", &webp), "image/webp");
        assert_eq!(derive("blob", b"GIF89a"), "image/gif");
        assert_eq!(derive("blob", b"%PDF-1.7"), "application/pdf");
    }

    #[test]
    fn falls_back_to_octet_stream() {
        assert_eq!(derive("mystery", &[0, 1, 2]), DEFAULT_CONTENT_TYPE);
        assert_eq!(derive("noext", &[]), DEFAULT_CONTENT_TYPE);
    }
}
