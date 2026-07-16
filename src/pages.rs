//! Branded HTML documents for the two non-success outcomes, so a consuming webview
//! can render something meaningful instead of a crash.
//!
//! These are strictly for the RENDER path (e.g. `resolveObjectUrl`). They are NOT
//! how a program distinguishes outcomes — that is the typed
//! [`crate::ResolveOutcome`]. The two pages are deliberately, unmistakably
//! different:
//!
//! * [`unreachable_html`] — a friendly, RETRYABLE "DIG Network unreachable" page
//!   with a **Connect to Node** call to action. Nothing was fetched; the network
//!   was down.
//! * [`integrity_failure_html`] — a hard SECURITY page: "Integrity Verification
//!   Failed". Bytes WERE fetched but did not verify against the chain-anchored root
//!   (tampered / decoy / wrong root / decrypt-verify failure). It reads as a
//!   security failure and offers NO "retry" affordance — the content is never shown.

/// The default "Connect to Node" target — the DIG install/connect landing. A
/// consuming app can override it via [`crate::ResolveOptions::connect_url`].
pub const DEFAULT_CONNECT_URL: &str = "https://dig.net";

/// The `text/html` MIME the branded pages are served as.
pub const HTML_CONTENT_TYPE: &str = "text/html";

/// Minimal HTML-attribute/text escaping so an app-supplied string cannot break out
/// of its `href`/text context.
fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Shared page chrome: a self-contained dark DIG-brand document (inline styles, no
/// external assets) so it renders in any sandboxed webview/iframe with no network.
fn page(accent: &str, glow: &str, brand_tag: &str, heading: &str, body_html: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{heading}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  html, body {{ height: 100%; margin: 0; }}
  body {{
    display: flex; align-items: center; justify-content: center;
    min-height: 100%; padding: 24px;
    background: radial-gradient(1200px 600px at 50% -10%, {glow} 0%, #0a0f1e 60%, #070a14 100%);
    color: #e8ecf6;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  }}
  main {{ width: 100%; max-width: 30rem; text-align: center; }}
  .brand {{
    font-size: 0.8125rem; letter-spacing: 0.18em; text-transform: uppercase;
    color: {accent}; margin: 0 0 1.25rem;
  }}
  .brand b {{ color: #cdd6f0; font-weight: 700; }}
  h1 {{ font-size: 1.5rem; line-height: 1.25; margin: 0 0 0.75rem; color: #ffffff; }}
  p {{ font-size: 1rem; line-height: 1.6; margin: 0 0 1.75rem; color: #aeb7d4; }}
  a.cta {{
    display: inline-block; padding: 0.75rem 1.5rem; border-radius: 0.625rem;
    background: {accent}; color: #ffffff; font-weight: 600; font-size: 1rem;
    text-decoration: none; transition: background 120ms ease;
  }}
  a.cta:focus-visible {{ outline: 3px solid #9fb8ff; outline-offset: 3px; }}
  @media (prefers-reduced-motion: reduce) {{ a.cta {{ transition: none; }} }}
</style>
</head>
<body>
<main role="main">
  <p class="brand">{brand_tag}</p>
  <h1>{heading}</h1>
  {body_html}
</main>
</body>
</html>
"##
    )
}

/// The friendly, retryable network-unreachable page with a Connect-to-Node CTA.
pub fn unreachable_html(connect_url: &str) -> String {
    let href = escape(connect_url);
    page(
        "#3b6cf6",
        "#14213a",
        "<b>DIG</b> Network",
        "DIG Network unreachable",
        &format!(
            r##"<p>We couldn't reach a DIG node or the public gateway to load this content. Connect a local DIG node to view it — it's faster and fully decentralized.</p>
  <a class="cta" href="{href}" rel="noopener noreferrer">Connect to Node</a>"##
        ),
    )
}

/// The hard SECURITY page: the served bytes failed integrity verification. No
/// content is shown and there is deliberately NO retry affordance.
pub fn integrity_failure_html() -> String {
    page(
        "#e5484d",
        "#3a1416",
        "<b>DIG</b> Network · Security",
        "Integrity Verification Failed",
        r##"<p role="alert">The content served for this address did not match its on-chain fingerprint. It may have been tampered with or served by an impostor, so it was <strong>not displayed</strong>. This is a security protection — the verified content could not be produced.</p>"##,
    )
}
