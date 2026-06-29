//! The SSO vault surface: list, reveal (audited), put a new version, delete, and version history.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the admin and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Sanctum is internal-only). This is a PERSONAL
//! vault — every signed-in admin sees every path (there is no per-owner scoping of secrets); the
//! writer subject is recorded only for display/audit.
//!
//! Secret PATHS travel in the URL as a SINGLE percent-encoded `{path}` segment (so `db/prod/pw`
//! rides inside one route param). State-changing POSTs (create / put / delete) carry a double-submit
//! CSRF token. Revealing a value (`GET /s/{path}` or `GET /s/{path}/v/{version}`) is an explicit,
//! AUDITED action; the value is decrypted server-side and shown masked, unmasked client-side only on
//! an explicit click.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth::{self, Identity};
use crate::config::{MAX_PATH_CHARS, MAX_VALUE_CHARS};
use crate::error::AppError;
use crate::handlers::{esc, fmt_ts, pct_encode, userbox, APP_CSS, SHIELD_SVG};
use crate::model::{SecretMeta, SecretVersion, VersionInfo};
use crate::{now_secs, AppState};

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const SECRET_HTML: &str = include_str!("../../templates/secret.html");
const REVEAL_HTML: &str = include_str!("../../templates/reveal.html");

/// Fixed mask shown until an explicit client-side reveal.
const MASK: &str = "••••••••••••";

// ---------------------------------------------------------------------------
// GET / — list secret paths (no values)
// ---------------------------------------------------------------------------

/// `GET /` — render the vault list (paths + latest version + last-write, NO values) and the
/// new-secret form.
pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let secrets = state.store.list_secrets().await.unwrap_or_default();
    let html = render_index(&who, &csrf, &secrets);
    html_with_csrf(StatusCode::OK, html, &csrf)
}

// ---------------------------------------------------------------------------
// POST / — create or update a secret from the index form (path + value)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub value: String,
}

/// `POST /` — validate the path, seal + store the value as a new version, then 302 to the secret's
/// detail page. CSRF-checked.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let path = validate_path(&form.path)?;
    do_put(&state, &who, &path, &form.value).await?;
    Ok(redirect_found(&format!("/s/{}", pct_encode(&path))))
}

// ---------------------------------------------------------------------------
// GET /s/{path} — reveal the latest value (audited) + detail/history
// ---------------------------------------------------------------------------

/// `GET /s/{path}` — reveal the LATEST value (decrypt + AUDIT), and render the detail page with the
/// version history, the add-version form, and the delete control.
pub async fn reveal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let path = validate_path(&raw_path)?;

    let latest = match state.store.get_latest(&path).await? {
        Some(v) => v,
        None => return Err(AppError::NotFound("No secret exists at that path.".to_string())),
    };
    let value = state.cipher.open_secret(&latest.ciphertext)?;

    // Revealing a value is an explicit, sensitive action — record WHO/WHICH/WHEN (never the value).
    state.audit.emit(AuditEvent::notice(
        "secret.reveal",
        &who.email,
        &path,
        &format!("v{}", latest.version),
    ));

    let history = state.store.list_versions(&path).await?;
    let csrf = auth::new_csrf_token();
    let html = render_detail(&who, &csrf, &path, &latest, &value, &history);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// GET /s/{path}/v/{version} — reveal a specific historical version (audited)
// ---------------------------------------------------------------------------

/// `GET /s/{path}/v/{version}` — reveal one historical version (decrypt + AUDIT) on a compact page.
pub async fn reveal_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_path, version)): Path<(String, i64)>,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let path = validate_path(&raw_path)?;

    let row = match state.store.get_version(&path, version).await? {
        Some(v) => v,
        None => return Err(AppError::NotFound("No such version.".to_string())),
    };
    let value = state.cipher.open_secret(&row.ciphertext)?;

    state.audit.emit(AuditEvent::notice(
        "secret.reveal",
        &who.email,
        &path,
        &format!("v{version}"),
    ));

    let csrf = auth::new_csrf_token();
    let html = render_reveal_version(&who, &csrf, &path, &row, &value);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
}

// ---------------------------------------------------------------------------
// POST /s/{path} — add a new version
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PutForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub value: String,
}

/// `POST /s/{path}` — seal + store the value as a new version, then 302 back to the detail page.
/// CSRF-checked.
pub async fn put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
    Form(form): Form<PutForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let path = validate_path(&raw_path)?;
    do_put(&state, &who, &path, &form.value).await?;
    Ok(redirect_found(&format!("/s/{}", pct_encode(&path))))
}

// ---------------------------------------------------------------------------
// POST /s/{path}/delete — delete a secret and all versions
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

/// `POST /s/{path}/delete` — delete the path and every version, then 302 to the list. CSRF-checked.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let path = validate_path(&raw_path)?;

    if !state.store.delete_secret(&path).await? {
        return Err(AppError::NotFound("No secret exists at that path.".to_string()));
    }
    state.audit.emit(AuditEvent::warning(
        "secret.delete",
        &who.email,
        &path,
        "all versions removed",
    ));
    Ok(redirect_found("/"))
}

// ---------------------------------------------------------------------------
// Shared logic
// ---------------------------------------------------------------------------

/// Seal `value` and append it as a new version of `path`, emitting a `secret.put` audit event.
async fn do_put(
    state: &AppState,
    who: &Identity,
    path: &str,
    value: &str,
) -> Result<i64, AppError> {
    if value.is_empty() {
        return Err(AppError::BadRequest("Enter a value to store.".to_string()));
    }
    if value.chars().count() > MAX_VALUE_CHARS {
        return Err(AppError::BadRequest("That value is too large.".to_string()));
    }
    let ciphertext = state.cipher.seal_secret(value)?;
    let version = state
        .store
        .put_secret(path, &ciphertext, &who.subject, now_secs())
        .await?;
    state.audit.emit(AuditEvent::info(
        "secret.put",
        &who.email,
        path,
        &format!("v{version}"),
    ));
    Ok(version)
}

/// Reject the request when the double-submit CSRF token does not match the cookie.
fn require_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    if auth::verify_csrf(headers, submitted) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Your session token expired. Reload the page and try again.".to_string(),
        ))
    }
}

/// Validate + normalize a secret path: 1..=`MAX_PATH_CHARS` chars of `[A-Za-z0-9._/-]`, no leading
/// or trailing `/`, and no empty / `.` / `..` segments (so it stays a clean, traversal-free key).
pub fn validate_path(raw: &str) -> Result<String, AppError> {
    let path = raw.trim();
    if path.is_empty() {
        return Err(AppError::BadRequest("Enter a secret path.".to_string()));
    }
    if path.chars().count() > MAX_PATH_CHARS {
        return Err(AppError::BadRequest("That secret path is too long.".to_string()));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(AppError::BadRequest(
            "A secret path must not start or end with '/'.".to_string(),
        ));
    }
    if !path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
    {
        return Err(AppError::BadRequest(
            "A secret path may use letters, digits, and . _ - / only.".to_string(),
        ));
    }
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(AppError::BadRequest(
            "A secret path has an empty or '.'/'..' segment.".to_string(),
        ));
    }
    Ok(path.to_string())
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Wrap rendered HTML in a response that also (re)sets the CSRF cookie.
fn html_with_csrf(status: StatusCode, html: String, csrf: &str) -> Response {
    (
        status,
        [(header::SET_COOKIE, auth::csrf_cookie(csrf))],
        Html(html),
    )
        .into_response()
}

/// A `302 Found` redirect to `location`.
fn redirect_found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_index(who: &Identity, csrf: &str, secrets: &[SecretMeta]) -> String {
    let count = match secrets.len() {
        1 => "1 secret".to_string(),
        n => format!("{n} secrets"),
    };
    INDEX_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Vault", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{LIST}}", &render_secret_list(secrets))
}

fn render_secret_list(secrets: &[SecretMeta]) -> String {
    if secrets.is_empty() {
        return "<li class=\"secret-item secret-item--empty\">No secrets yet. Add one to get started.</li>".to_string();
    }
    secrets
        .iter()
        .map(|m| {
            let enc = pct_encode(&m.path);
            format!(
                "<li class=\"secret-item\">\
                   <div class=\"secret-main\">\
                     <a class=\"secret-path\" href=\"/s/{enc}\">{path}</a>\
                     <div class=\"secret-meta\"><span class=\"badge badge--version\">v{ver}</span>\
                       <span>updated {updated}</span></div>\
                   </div>\
                   <span class=\"secret-mask\" aria-hidden=\"true\">{mask}</span>\
                   <a class=\"btn btn-secondary btn-sm\" href=\"/s/{enc}\">Open</a>\
                 </li>",
                enc = esc(&enc),
                path = esc(&m.path),
                ver = m.latest_version,
                updated = esc(&fmt_ts(m.updated_at)),
                mask = MASK,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_detail(
    who: &Identity,
    csrf: &str,
    path: &str,
    latest: &SecretVersion,
    value: &str,
    history: &[VersionInfo],
) -> String {
    let enc = pct_encode(path);
    SECRET_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Vault", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        // PATH_ENC is used inside double-quoted href/action attributes; esc() neutralizes quotes.
        .replace("{{PATH_ENC}}", &esc(&enc))
        .replace("{{PATH}}", &esc(path))
        .replace("{{LATEST_VERSION}}", &latest.version.to_string())
        .replace("{{UPDATED}}", &esc(&fmt_ts(latest.created_at)))
        .replace("{{CREATED_BY}}", &esc(&latest.created_by))
        .replace("{{VERSION_COUNT}}", &history.len().to_string())
        .replace("{{MASK}}", MASK)
        // The plaintext lives ONLY in the data-value attribute (attribute-escaped); it is shown
        // masked and unmasked client-side on click.
        .replace("{{VALUE_ATTR}}", &esc(value))
        .replace("{{HISTORY}}", &render_history(path, history))
}

fn render_history(path: &str, history: &[VersionInfo]) -> String {
    if history.is_empty() {
        return "<li class=\"version-item version-item--empty\">No versions.</li>".to_string();
    }
    let enc = pct_encode(path);
    history
        .iter()
        .map(|v| {
            format!(
                "<li class=\"version-item\">\
                   <div class=\"version-main\"><span class=\"badge badge--version\">v{ver}</span>\
                     <span class=\"version-when\">{when}</span>\
                     <span class=\"version-by\">{by}</span></div>\
                   <a class=\"btn btn-ghost btn-sm\" href=\"/s/{enc}/v/{ver}\">Reveal</a>\
                 </li>",
                ver = v.version,
                when = esc(&fmt_ts(v.created_at)),
                by = esc(&v.created_by),
                enc = esc(&enc),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_reveal_version(
    who: &Identity,
    _csrf: &str,
    path: &str,
    row: &SecretVersion,
    value: &str,
) -> String {
    let enc = pct_encode(path);
    REVEAL_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Vault", Some(&who.email)))
        .replace("{{PATH_ENC}}", &esc(&enc))
        .replace("{{PATH}}", &esc(path))
        .replace("{{VERSION}}", &row.version.to_string())
        .replace("{{WHEN}}", &esc(&fmt_ts(row.created_at)))
        .replace("{{CREATED_BY}}", &esc(&row.created_by))
        .replace("{{MASK}}", MASK)
        .replace("{{VALUE_ATTR}}", &esc(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_validation_accepts_hierarchical_paths() {
        assert_eq!(validate_path(" db/prod/password ").unwrap(), "db/prod/password");
        assert_eq!(validate_path("api.key-1").unwrap(), "api.key-1");
    }

    #[test]
    fn path_validation_rejects_bad_paths() {
        for bad in ["", "/leading", "trailing/", "a//b", "a/../b", "has space", "ta\tb", "uni©de"] {
            assert!(validate_path(bad).is_err(), "should reject {bad:?}");
        }
    }
}
