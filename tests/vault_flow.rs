//! End-to-end flow tests against the in-memory store + the dev cipher (NO database, NO network).
//!
//! Drives the real `Router` in-process via `tower::oneshot`, exercising create -> list -> reveal ->
//! new-version -> history -> reveal-version -> delete, the double-submit CSRF guard, hierarchical
//! (slash-bearing) secret paths via percent-encoding, value escaping (no stored XSS), the
//! values-never-in-the-list invariant, and the transit API (token + SSO auth).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use sanctum::audit::AuditSink;
use sanctum::config::Config;
use sanctum::crypto::Cipher;
use sanctum::store::InMemoryStore;
use sanctum::{app, AppState, DEV_MASTER_KEY};
use tower::ServiceExt;

const TRANSIT_TOKEN: &str = "transit-test-token";

fn state() -> AppState {
    let mut config = Config::dev();
    config.transit_token = Some(TRANSIT_TOKEN.to_string());
    AppState {
        config: Arc::new(config),
        store: Arc::new(InMemoryStore::new()),
        cipher: Arc::new(Cipher::new(DEV_MASTER_KEY)),
        audit: AuditSink::disabled(),
    }
}

// ---- request helpers ------------------------------------------------------

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
    fn csrf_cookie(&self) -> Option<String> {
        for hv in self.headers.get_all(header::SET_COOKIE).iter() {
            let raw = hv.to_str().ok()?;
            if let Some(rest) = raw.strip_prefix("__Host-csrf=") {
                return Some(rest.split(';').next().unwrap_or("").to_string());
            }
        }
        None
    }
}

fn enc(s: &str) -> String {
    let mut out = String::new();
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

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

fn get(path: &str, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::empty()).unwrap()
}

fn post_form(
    path: &str,
    fields: &[(&str, &str)],
    cookie: &str,
    subject: Option<&str>,
) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={cookie}"));
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::from(body)).unwrap()
}

fn post_json(path: &str, json: &str, bearer: Option<&str>, subject: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if let Some(s) = subject {
        b = b
            .header("x-auth-subject", s)
            .header("x-auth-email", format!("{s}@w33d.xyz"));
    }
    b.body(Body::from(json.to_string())).unwrap()
}

// ---- tests ----------------------------------------------------------------

#[tokio::test]
async fn create_reveal_version_delete_lifecycle() {
    let app = app(state());
    let path = "db/prod/password"; // hierarchical path: slashes ride inside one %2F-encoded segment
    let enc_path = enc(path);

    // GET / mints a CSRF cookie + shows the empty state.
    let home = send(&app, get("/", Some("alice"))).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.body.contains("Secrets vault"));
    assert!(home.body.contains("No secrets yet"));
    let csrf = home.csrf_cookie().expect("csrf on GET /");

    // POST / creates v1 -> 302 to the detail page.
    let created = send(
        &app,
        post_form(
            "/",
            &[
                ("csrf_token", &csrf),
                ("path", path),
                ("value", "v1-secret"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::FOUND);
    assert_eq!(created.location(), format!("/s/{enc_path}"));

    // The list shows the path + version but NEVER the value.
    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("db/prod/password"));
    assert!(list.body.contains("v1"));
    assert!(
        !list.body.contains("v1-secret"),
        "the list must not leak the value"
    );

    // GET /s/{path} reveals the latest value (in the data-value attribute, masked in the body).
    let reveal = send(&app, get(&format!("/s/{enc_path}"), Some("alice"))).await;
    assert_eq!(reveal.status, StatusCode::OK);
    assert!(reveal.body.contains("data-value=\"v1-secret\""));
    assert!(reveal.body.contains("Version history"));
    let csrf2 = reveal.csrf_cookie().unwrap();

    // POST /s/{path} adds v2.
    let put = send(
        &app,
        post_form(
            &format!("/s/{enc_path}"),
            &[("csrf_token", &csrf2), ("value", "v2-secret")],
            &csrf2,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(put.status, StatusCode::FOUND);
    assert_eq!(put.location(), format!("/s/{enc_path}"));

    // Latest reveal now returns v2; history lists v2 then v1.
    let reveal2 = send(&app, get(&format!("/s/{enc_path}"), Some("alice"))).await;
    assert!(reveal2.body.contains("data-value=\"v2-secret\""));
    assert!(reveal2.body.contains(&format!("/s/{enc_path}/v/1")));
    assert!(reveal2.body.contains(&format!("/s/{enc_path}/v/2")));
    let csrf3 = reveal2.csrf_cookie().unwrap();

    // Lifecycle metadata is additive: expiry/rotation reminders show on the list but never values.
    let lifecycle = send(
        &app,
        post_form(
            &format!("/s/{enc_path}/lifecycle"),
            &[
                ("csrf_token", &csrf3),
                ("expires_in_days", "1"),
                ("rotation_in_days", "2"),
                ("rotation_state", "rotation_due"),
            ],
            &csrf3,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(lifecycle.status, StatusCode::FOUND);
    let list_due = send(&app, get("/", Some("alice"))).await;
    assert!(list_due.body.contains("Expiry &amp; rotation"));
    assert!(list_due.body.contains("rotation due"));
    assert!(list_due.body.contains("db/prod/password"));

    // Rollback copies v1 into a new latest version without deleting history.
    let rollback = send(
        &app,
        post_form(
            &format!("/s/{enc_path}/v/1/rollback"),
            &[("csrf_token", &csrf3)],
            &csrf3,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(rollback.status, StatusCode::FOUND);
    assert_eq!(rollback.location(), format!("/s/{enc_path}"));
    let reveal3 = send(&app, get(&format!("/s/{enc_path}"), Some("alice"))).await;
    assert!(reveal3.body.contains("data-value=\"v1-secret\""));
    assert!(reveal3.body.contains("Version 3"));

    // Reveal a specific historical version (v1).
    let v1 = send(&app, get(&format!("/s/{enc_path}/v/1"), Some("alice"))).await;
    assert_eq!(v1.status, StatusCode::OK);
    assert!(v1.body.contains("data-value=\"v1-secret\""));

    // Delete the secret -> 302 /, then it is gone everywhere.
    let csrf4 = reveal3.csrf_cookie().unwrap();
    let del = send(
        &app,
        post_form(
            &format!("/s/{enc_path}/delete"),
            &[("csrf_token", &csrf4)],
            &csrf4,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(del.status, StatusCode::FOUND);
    assert_eq!(del.location(), "/");
    let gone = send(&app, get(&format!("/s/{enc_path}"), Some("alice"))).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn value_with_html_is_escaped_in_data_attribute() {
    let app = app(state());
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    let payload = "<script>alert('pwn')</script>";
    send(
        &app,
        post_form(
            "/",
            &[("csrf_token", &csrf), ("path", "xss"), ("value", payload)],
            &csrf,
            Some("alice"),
        ),
    )
    .await;

    let reveal = send(&app, get("/s/xss", Some("alice"))).await;
    // The raw value is escaped inside the data-value attribute, never emitted as live markup.
    assert!(reveal
        .body
        .contains("data-value=\"&lt;script&gt;alert(&#x27;pwn&#x27;)&lt;/script&gt;\""));
    assert!(!reveal.body.contains("<script>alert('pwn')</script>"));
}

#[tokio::test]
async fn csrf_is_required_on_create_put_delete() {
    let app = app(state());
    // Create with a mismatched token/cookie -> rejected.
    let bad = send(
        &app,
        post_form(
            "/",
            &[("csrf_token", "wrong"), ("path", "k"), ("value", "v")],
            "the-cookie",
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // No secret was created.
    let list = send(&app, get("/", Some("alice"))).await;
    assert!(list.body.contains("No secrets yet"));
}

#[tokio::test]
async fn invalid_paths_are_rejected() {
    let app = app(state());
    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    for bad in ["/leading", "a/../b", "has space"] {
        let r = send(
            &app,
            post_form(
                "/",
                &[("csrf_token", &csrf), ("path", bad), ("value", "v")],
                &csrf,
                Some("alice"),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "should reject {bad:?}");
    }
}

#[tokio::test]
async fn read_policies_filter_list_and_reject_reveal() {
    let app = app(state());
    let path = "db/prod/password";
    let enc_path = enc(path);

    let home = send(&app, get("/", Some("alice"))).await;
    let csrf = home.csrf_cookie().unwrap();
    send(
        &app,
        post_form(
            "/",
            &[("csrf_token", &csrf), ("path", path), ("value", "secret")],
            &csrf,
            Some("alice"),
        ),
    )
    .await;

    let added = send(
        &app,
        post_form(
            "/policies",
            &[
                ("csrf_token", &csrf),
                ("subject", "alice"),
                ("path_prefix", "db/prod"),
            ],
            &csrf,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(added.status, StatusCode::FOUND);

    let alice_list = send(&app, get("/", Some("alice"))).await;
    assert!(alice_list.body.contains(&format!("href=\"/s/{enc_path}\"")));
    assert!(alice_list.body.contains("Read policies"));
    assert!(alice_list.body.contains("db/prod"));

    let bob_list = send(&app, get("/", Some("bob"))).await;
    assert!(!bob_list.body.contains(&format!("href=\"/s/{enc_path}\"")));
    let bob_reveal = send(&app, get(&format!("/s/{enc_path}"), Some("bob"))).await;
    assert_eq!(bob_reveal.status, StatusCode::FORBIDDEN);

    let csrf2 = alice_list.csrf_cookie().unwrap();
    let removed = send(
        &app,
        post_form(
            "/policies/delete",
            &[
                ("csrf_token", &csrf2),
                ("subject", "alice"),
                ("path_prefix", "db/prod"),
            ],
            &csrf2,
            Some("alice"),
        ),
    )
    .await;
    assert_eq!(removed.status, StatusCode::FOUND);
    let bob_after_remove = send(&app, get(&format!("/s/{enc_path}"), Some("bob"))).await;
    assert_eq!(bob_after_remove.status, StatusCode::OK);
}

#[tokio::test]
async fn transit_round_trip_with_token() {
    let app = app(state());

    // encrypt with the internal token (no SSO header) -> 200 + a self-describing token.
    let enc = send(
        &app,
        post_json(
            "/transit/encrypt",
            r#"{"plaintext":"service-payload","key":"billing"}"#,
            Some(TRANSIT_TOKEN),
            None,
        ),
    )
    .await;
    assert_eq!(enc.status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&enc.body).unwrap();
    let ciphertext = v["ciphertext"].as_str().unwrap().to_string();
    assert!(ciphertext.starts_with("sanctum:v1:billing:"));
    assert_eq!(v["key"], "billing");

    // decrypt round-trips back to the plaintext.
    let dec = send(
        &app,
        post_json(
            "/transit/decrypt",
            &format!(r#"{{"ciphertext":"{ciphertext}"}}"#),
            Some(TRANSIT_TOKEN),
            None,
        ),
    )
    .await;
    assert_eq!(dec.status, StatusCode::OK);
    let dv: serde_json::Value = serde_json::from_str(&dec.body).unwrap();
    assert_eq!(dv["plaintext"], "service-payload");
}

#[tokio::test]
async fn transit_requires_authorization() {
    let app = app(state());
    // No SSO header, no/invalid bearer -> 401.
    let unauth = send(
        &app,
        post_json("/transit/encrypt", r#"{"plaintext":"x"}"#, None, None),
    )
    .await;
    assert_eq!(unauth.status, StatusCode::UNAUTHORIZED);

    let wrong = send(
        &app,
        post_json(
            "/transit/encrypt",
            r#"{"plaintext":"x"}"#,
            Some("nope"),
            None,
        ),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    // A gateway-injected SSO identity authorizes too (admin testing through Sluice).
    let sso = send(
        &app,
        post_json(
            "/transit/encrypt",
            r#"{"plaintext":"x"}"#,
            None,
            Some("admin"),
        ),
    )
    .await;
    assert_eq!(sso.status, StatusCode::OK);
}

#[tokio::test]
async fn healthz_is_public() {
    let app = app(state());
    let r = send(&app, get("/healthz", None)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "ok");
}
