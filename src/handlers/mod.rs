//! HTTP handlers + shared server-render helpers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`secrets`] — the SSO vault surface (list, reveal, put, delete, version history).
//! - [`transit`] — the internal transit API (`/transit/encrypt`, `/transit/decrypt`).
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand: brand gradient, indigo accent, cards, buttons, the
//! app-bar with the shield + wordmark + signed-in email + gateway logout. Every secret PATH /
//! version metadata is HTML-escaped on render; a revealed VALUE is only ever placed into a
//! data-attribute and unmasked client-side on an explicit click (never auto-shown).

pub mod health;
pub mod secrets;
pub mod transit;

use axum::http::StatusCode;
use axum::response::Html;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Cross-subdomain SSO logout (terminated at the Keystone IdP behind the gateway).
pub const LOGOUT_URL: &str = "https://id.w33d.xyz/_gw/auth/logout";

/// Branded error page shell.
const ERROR_HTML: &str = include_str!("../../templates/error.html");

/// Format epoch seconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

/// The right side of the app-bar: a page title, the signed-in email (when known), and the
/// cross-subdomain logout link. Shared by every page so the chrome stays identical.
pub fn userbox(title: &str, email: Option<&str>) -> String {
    let email_span = match email {
        Some(e) if !e.is_empty() => format!("<span class=\"user-email\">{}</span>", esc(e)),
        _ => String::new(),
    };
    format!(
        "<span class=\"topbar__title\">{title}</span>{email_span}<a class=\"btn btn-ghost btn-sm\" href=\"{LOGOUT_URL}\">Log out</a>",
        title = esc(title),
    )
}

/// Render the branded error page. `email` is shown in the app-bar when a gateway identity is known.
pub fn render_error(
    status: StatusCode,
    heading: &str,
    message: &str,
    email: Option<&str>,
) -> (StatusCode, Html<String>) {
    let body = ERROR_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Vault", email))
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(heading))
        .replace("{{MESSAGE}}", &esc(message));
    (status, Html(body))
}

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth against XSS).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode a string for use as a SINGLE URL path segment: everything except the RFC 3986
/// unreserved set (`A-Za-z0-9-._~`) is `%XX`-escaped — including `/`, so a hierarchical secret path
/// like `db/prod/password` rides inside one `{path}` route segment and the `Path` extractor decodes
/// it back intact.
pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn pct_encode_escapes_slashes_and_specials() {
        assert_eq!(pct_encode("db/prod/password"), "db%2Fprod%2Fpassword");
        assert_eq!(pct_encode("a b"), "a%20b");
        assert_eq!(pct_encode("safe-._~AZ09"), "safe-._~AZ09");
    }
}
