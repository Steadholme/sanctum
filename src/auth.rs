//! Gateway-injected identity, double-submit CSRF, and transit-token authorization.
//!
//! Sanctum does NO login of its own. The management UI sits behind a Sluice `auth=sso` route,
//! where the gateway runs the OIDC browser login against Keystone, STRIPS any inbound `X-Auth-*`,
//! and injects the verified `X-Auth-Subject` / `X-Auth-Email`. Because Sanctum is internal-only
//! (never publicly reachable), it TRUSTS those headers as the signed-in admin.
//!
//! State-changing POSTs (put / delete) are additionally guarded by a double-submit CSRF token: the
//! same opaque value is set as the `__Host-csrf` cookie and embedded in the form; the POST is
//! accepted only when the submitted field equals the cookie.
//!
//! The `/transit/*` API has a SECOND authorization path for in-network service-to-service callers:
//! a `Authorization: Bearer <TRANSIT_TOKEN>` that matches the configured token (constant-time),
//! for callers that reach Sanctum directly on the `holdfast` network without going through the
//! SSO gateway.

use axum::http::{header, HeaderMap};

use crate::random_alnum;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_GROUPS: &str = "x-auth-groups";
/// HMAC minted by Sluice binding the injected identity to a 1-minute window.
pub const HEADER_SIG: &str = "x-auth-sig";

/// Dev/test fallback identity used ONLY when no gateway headers are present (local `cargo run` or
/// the DB-free test suite). In production every request arrives with `X-Auth-*` injected.
pub const DEV_SUBJECT: &str = "dev-user";
pub const DEV_EMAIL: &str = "dev@sanctum.local";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser only
/// ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;
/// CSRF token length (characters from the 62-symbol alphabet ~= 238 bits).
const CSRF_LEN: usize = 40;

/// The authenticated admin. Subject is the stable id; email is display-only.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

/// Resolve the current admin from the gateway-injected headers, falling back to the dev identity
/// when none are present (so the service still runs DB-free locally and in tests).
///
/// SAFETY INVARIANT: the `dev-user` fallback must never be reachable in production. It is safe
/// only because every route that reads or mutates a secret sits behind
/// [`require_signed_identity`] in [`crate::app`], which rejects a request with no verified
/// `X-Auth-Subject` before any handler runs. **A new route that touches secrets must be added to
/// the guarded router**, not the open one, or it will silently run as `dev-user`.
pub fn identity(headers: &HeaderMap) -> Identity {
    Identity {
        subject: header_value(headers, HEADER_SUBJECT).unwrap_or_else(|| DEV_SUBJECT.to_string()),
        email: header_value(headers, HEADER_EMAIL).unwrap_or_else(|| DEV_EMAIL.to_string()),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parse a `Authorization: Bearer <token>` header, returning the token.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Authorize a `/transit/*` request. Two accepted paths:
///   1. SSO: a gateway-injected `X-Auth-Subject` is present (the gateway strips inbound copies, so
///      its presence means an authenticated browser session via Sluice).
///   2. Token: a `Bearer` that matches the configured `TRANSIT_TOKEN` (constant-time).
///
/// When no `TRANSIT_TOKEN` is configured, only path (1) authorizes. With neither an SSO header nor
/// a matching token, the request is rejected (401).
pub fn transit_authorized(
    headers: &HeaderMap,
    transit_token: Option<&str>,
    gateway_key: Option<&str>,
    enforce_signature: bool,
) -> bool {
    // SSO path. The mere PRESENCE of X-Auth-Subject proves nothing: any peer that can reach
    // this container can set that header. It counts only when Sluice actually signed it.
    if header_value(headers, HEADER_SUBJECT).is_some()
        && gateway_identity_ok(headers, gateway_key, enforce_signature)
    {
        return true;
    }
    // Service-to-service path: a constant-time bearer match.
    match (bearer_token(headers), transit_token) {
        (Some(presented), Some(cfg)) if !cfg.is_empty() => {
            ct_eq(presented.as_bytes(), cfg.as_bytes())
        }
        _ => false,
    }
}

/// Verify Sluice's `X-Auth-Sig` over the injected identity.
///
/// Byte-identical to Sluice's `auth.SignIdentity` (Go): lowercase-hex HMAC-SHA256 over
/// `subject "\n" groups "\n" epoch-minute`, accepted for the current or previous minute.
///
/// FAIL CLOSED, unlike the permissive variants elsewhere in the estate: when enforcement is on,
/// a missing key, a missing subject or a missing signature all return false. Sanctum is a secrets
/// vault — "no key configured" must never mean "trust everyone".
pub fn gateway_identity_ok(
    headers: &HeaderMap,
    gateway_key: Option<&str>,
    enforce_signature: bool,
) -> bool {
    if !enforce_signature {
        return true;
    }
    let Some(key) = gateway_key.filter(|k| !k.is_empty()) else {
        return false;
    };
    let Some(subject) = header_value(headers, HEADER_SUBJECT) else {
        return false;
    };
    let Some(sig) = header_value(headers, HEADER_SIG) else {
        return false;
    };
    let groups = header_value(headers, HEADER_GROUPS).unwrap_or_default();
    let window = now_unix() / 60;
    [window, window - 1].iter().any(|&w| {
        ct_eq(
            sig.as_bytes(),
            sign_identity(key, &subject, &groups, w).as_bytes(),
        )
    })
}

/// Byte-identical to Sluice's `sign_identity` in `sluice/internal/auth/sig.go`: lowercase-hex
/// HMAC-SHA256 over `subject "\n" groups "\n" epoch-minute`. Public so tests can mint a genuine
/// gateway signature instead of asserting against a hand-copied constant.
pub fn sign_identity(key: &str, subject: &str, groups: &str, window: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(subject.as_bytes());
    mac.update(b"\n");
    mac.update(groups.as_bytes());
    mac.update(b"\n");
    mac.update(window.to_string().as_bytes());
    let out = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Seconds since the Unix epoch; `/ 60` gives the signing window.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Mint a fresh CSRF token (same value goes in the cookie and the form field).
pub fn new_csrf_token() -> String {
    random_alnum(CSRF_LEN)
}

/// `Set-Cookie` value for the CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> bool {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    }
}

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// Length-checked constant-time byte comparison (no early return on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Reject any request to a console route whose gateway identity is absent or unsigned.
///
/// This is the vault's single enforcement point. Before it existed, `identity()` fell back to a
/// development subject when no headers were present, so ANY peer that could reach the container
/// — the gateway strips inbound `X-Auth-*` but only for traffic that goes THROUGH it — was
/// served the authenticated console. See the 2026-09-14 audit.
pub async fn require_signed_identity(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !state.config.enforce_gateway_signature {
        return next.run(request).await;
    }
    if gateway_identity_ok(
        request.headers(),
        state.config.gateway_hmac_key.as_deref(),
        true,
    ) {
        return next.run(request).await;
    }
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(axum::http::header::CACHE_CONTROL, "private, no-store")],
        "unauthorized: this endpoint requires a gateway-signed identity",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn identity_falls_back_to_dev() {
        let id = identity(&HeaderMap::new());
        assert_eq!(id.subject, DEV_SUBJECT);
        assert_eq!(id.email, DEV_EMAIL);
    }

    #[test]
    fn identity_reads_gateway_headers() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("user-42"));
        h.insert(HEADER_EMAIL, HeaderValue::from_static("a@w33d.xyz"));
        let id = identity(&h);
        assert_eq!(id.subject, "user-42");
        assert_eq!(id.email, "a@w33d.xyz");
    }

    #[test]
    fn csrf_double_submit() {
        let token = new_csrf_token();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&h, &token));
        assert!(!verify_csrf(&h, "not-the-token"));
        assert!(!verify_csrf(&HeaderMap::new(), &token));
    }

    #[test]
    fn transit_token_path() {
        let mut h = HeaderMap::new();
        // No SSO header, no token -> denied.
        assert!(!transit_authorized(&h, Some("s3cr3t"), None, false));
        // Wrong bearer -> denied.
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nope"),
        );
        assert!(!transit_authorized(&h, Some("s3cr3t"), None, false));
        // Right bearer -> allowed.
        let mut h2 = HeaderMap::new();
        h2.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cr3t"),
        );
        assert!(transit_authorized(&h2, Some("s3cr3t"), None, false));
    }

    #[test]
    fn transit_sso_path_requires_a_signed_identity() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("admin"));

        // Enforcement off (local run / tests): an injected subject is taken at face value.
        assert!(transit_authorized(&h, None, None, false));

        // Enforcement ON: a bare, unsigned X-Auth-Subject must NOT authorize. This is the
        // 2026-09-14 audit finding — any peer that reached the container could set this header
        // and obtain a decrypt oracle.
        assert!(!transit_authorized(&h, None, Some("k"), true));
        assert!(!transit_authorized(&h, Some("s3cr3t"), Some("k"), true));

        // With a real gateway signature it authorizes again.
        let mut signed = HeaderMap::new();
        signed.insert(HEADER_SUBJECT, HeaderValue::from_static("admin"));
        let window = now_unix() / 60;
        let sig = sign_identity("k", "admin", "", window);
        signed.insert(HEADER_SIG, HeaderValue::from_str(&sig).unwrap());
        assert!(transit_authorized(&signed, None, Some("k"), true));

        // The bearer path still works for service-to-service callers with no browser session.
        let mut bearer = HeaderMap::new();
        bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cr3t"),
        );
        assert!(transit_authorized(&bearer, Some("s3cr3t"), Some("k"), true));
    }

    #[test]
    fn gateway_signature_fails_closed() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, HeaderValue::from_static("admin"));

        // No key configured while enforcing -> reject. "Unconfigured" must never mean "trusted".
        assert!(!gateway_identity_ok(&h, None, true));
        assert!(!gateway_identity_ok(&h, Some(""), true));
        // Identity present but unsigned -> reject.
        assert!(!gateway_identity_ok(&h, Some("k"), true));
        // No identity at all -> reject (there is no anonymous console).
        assert!(!gateway_identity_ok(&HeaderMap::new(), Some("k"), true));

        // A signature minted for a different subject must not verify.
        let mut wrong = HeaderMap::new();
        wrong.insert(HEADER_SUBJECT, HeaderValue::from_static("admin"));
        let other = sign_identity("k", "someone-else", "", now_unix() / 60);
        wrong.insert(HEADER_SIG, HeaderValue::from_str(&other).unwrap());
        assert!(!gateway_identity_ok(&wrong, Some("k"), true));

        // Correct signature, current window, verifies. Groups participate in the MAC.
        let mut ok = HeaderMap::new();
        ok.insert(HEADER_SUBJECT, HeaderValue::from_static("admin"));
        ok.insert(HEADER_GROUPS, HeaderValue::from_static("admins"));
        let sig = sign_identity("k", "admin", "admins", now_unix() / 60);
        ok.insert(HEADER_SIG, HeaderValue::from_str(&sig).unwrap());
        assert!(gateway_identity_ok(&ok, Some("k"), true));
    }

    /// Cross-language contract. These are the exact vectors from Sluice's
    /// `internal/auth/sig_test.go::TestSignIdentityVectors`. If this test ever fails, Sanctum and
    /// the gateway have diverged and every signed request will be rejected in production.
    #[test]
    fn sign_identity_matches_the_gateway_vectors() {
        assert_eq!(
            sign_identity("test-key", "usr_alice", "admins,devs", 1),
            "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777"
        );
        assert_eq!(
            sign_identity("test-key", "usr_bob", "", 2),
            "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658"
        );
    }
}

// ---------------------------------------------------------------------------
// Enforcement layer
// ---------------------------------------------------------------------------
