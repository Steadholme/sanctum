//! The SSO vault surface: list, reveal (audited), put a new version, delete, version history,
//! rollback, read policies, and lifecycle reminders.
//!
//! Mounted behind a Sluice `auth=sso` route: the gateway authenticates the admin and injects
//! `X-Auth-Subject` / `X-Auth-Email`, which we trust (Sanctum is internal-only). This is a PERSONAL
//! vault — by default every signed-in admin sees every path. Additive read policies can narrow
//! which subjects may read which path prefixes; when no policies exist, legacy access remains.
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
use crate::handlers::{app_css, esc, fmt_ts, pct_encode, userbox, SHIELD_SVG};
use crate::model::{SecretLifecycle, SecretMeta, SecretReadPolicy, SecretVersion, VersionInfo};
use crate::{now_secs, AppState};

const INDEX_HTML: &str = include_str!("../../templates/index.html");
const SECRET_HTML: &str = include_str!("../../templates/secret.html");
const REVEAL_HTML: &str = include_str!("../../templates/reveal.html");

/// Fixed mask shown until an explicit client-side reveal.
const MASK: &str = "••••••••••••";
const DUE_HORIZON_SECS: i64 = 14 * 24 * 60 * 60;
const MAX_LIFECYCLE_DAYS: i64 = 3650;

// ---------------------------------------------------------------------------
// GET / — list secret paths (no values)
// ---------------------------------------------------------------------------

/// `GET /` — render the vault list (paths + latest version + last-write, NO values) and the
/// new-secret form.
pub async fn index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let who = auth::identity(&headers);
    let csrf = auth::new_csrf_token();
    let secrets = readable_secrets(&state, &who).await?;
    let lifecycles = state.store.list_lifecycle().await?;
    let policies = state.store.list_read_policies().await?;
    let now = now_secs();
    let html = render_index(&who, &csrf, &secrets, &lifecycles, &policies, now);
    Ok(html_with_csrf(StatusCode::OK, html, &csrf))
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

#[derive(Debug, Deserialize)]
pub struct PolicyForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub path_prefix: String,
}

#[derive(Debug, Deserialize)]
pub struct PolicyDeleteForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub path_prefix: String,
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
// POST /policies — add or update a read policy
// ---------------------------------------------------------------------------

/// `POST /policies` — upsert an additive read policy. CSRF-checked.
pub async fn add_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PolicyForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let subject = validate_subject(&form.subject)?;
    let path_prefix = validate_policy_prefix(&form.path_prefix)?;
    state
        .store
        .put_read_policy(&subject, &path_prefix, &who.subject, now_secs())
        .await?;
    state.audit.emit(AuditEvent::info(
        "secret.policy.put",
        &who.email,
        &path_prefix,
        &format!("subject={subject}"),
    ));
    Ok(redirect_found("/"))
}

// ---------------------------------------------------------------------------
// POST /policies/delete — delete a read policy
// ---------------------------------------------------------------------------

/// `POST /policies/delete` — remove one read policy. CSRF-checked.
pub async fn delete_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PolicyDeleteForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let subject = validate_subject(&form.subject)?;
    let path_prefix = validate_policy_prefix(&form.path_prefix)?;
    state
        .store
        .delete_read_policy(&subject, &path_prefix)
        .await?;
    state.audit.emit(AuditEvent::warning(
        "secret.policy.delete",
        &who.email,
        &path_prefix,
        &format!("subject={subject}"),
    ));
    Ok(redirect_found("/"))
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
    require_read_path(&state, &who, &path).await?;

    let latest = match state.store.get_latest(&path).await? {
        Some(v) => v,
        None => {
            return Err(AppError::NotFound(
                "No secret exists at that path.".to_string(),
            ))
        }
    };

    let now = now_secs();
    let lifecycle = state.store.get_lifecycle(&path).await?;
    if is_expired(lifecycle.as_ref(), now) {
        state.audit.emit(AuditEvent::warning(
            "secret.read.expired",
            &who.email,
            &path,
            &format!("v{}", latest.version),
        ));
        let history = state.store.list_versions(&path).await?;
        let csrf = auth::new_csrf_token();
        let html = render_detail(
            &who,
            &csrf,
            &path,
            &latest,
            None,
            &history,
            lifecycle.as_ref(),
            now,
        );
        return Ok(html_with_csrf(StatusCode::OK, html, &csrf));
    }

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
    let html = render_detail(
        &who,
        &csrf,
        &path,
        &latest,
        Some(value.as_str()),
        &history,
        lifecycle.as_ref(),
        now,
    );
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
    require_read_path(&state, &who, &path).await?;

    let row = match state.store.get_version(&path, version).await? {
        Some(v) => v,
        None => return Err(AppError::NotFound("No such version.".to_string())),
    };
    let now = now_secs();
    let lifecycle = state.store.get_lifecycle(&path).await?;
    if is_expired(lifecycle.as_ref(), now) {
        state.audit.emit(AuditEvent::warning(
            "secret.read.expired",
            &who.email,
            &path,
            &format!("v{version}"),
        ));
        let when = lifecycle
            .and_then(|l| l.expires_at)
            .map(fmt_ts)
            .unwrap_or_default();
        let msg = format!(
            "This secret expired on {when} and can no longer be revealed. Save a new version and clear or extend its expiry to restore access."
        );
        return Ok(crate::handlers::render_error(
            StatusCode::FORBIDDEN,
            "Secret expired",
            &msg,
            Some(&who.email),
        )
        .into_response());
    }

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

#[derive(Debug, Deserialize)]
pub struct LifecycleForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub expires_in_days: String,
    #[serde(default)]
    pub rotation_in_days: String,
    #[serde(default)]
    pub rotation_state: String,
}

#[derive(Debug, Deserialize)]
pub struct RollbackForm {
    #[serde(default)]
    pub csrf_token: String,
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
    require_read_path(&state, &who, &path).await?;
    do_put(&state, &who, &path, &form.value).await?;
    Ok(redirect_found(&format!("/s/{}", pct_encode(&path))))
}

// ---------------------------------------------------------------------------
// POST /s/{path}/lifecycle — update expiry / rotation reminders
// ---------------------------------------------------------------------------

/// `POST /s/{path}/lifecycle` — set or clear expiry and rotation reminders. CSRF-checked.
pub async fn lifecycle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
    Form(form): Form<LifecycleForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    let who = auth::identity(&headers);
    let path = validate_path(&raw_path)?;
    require_read_path(&state, &who, &path).await?;
    let now = now_secs();
    let expires_at = parse_optional_days(&form.expires_in_days, "Expiry", now)?;
    let rotation_due_at = parse_optional_days(&form.rotation_in_days, "Rotation reminder", now)?;
    let rotation_state = validate_rotation_state(&form.rotation_state)?;
    if !state
        .store
        .set_lifecycle(
            &path,
            expires_at,
            rotation_due_at,
            &rotation_state,
            &who.subject,
            now,
        )
        .await?
    {
        return Err(AppError::NotFound(
            "No secret exists at that path.".to_string(),
        ));
    }
    state.audit.emit(AuditEvent::info(
        "secret.lifecycle",
        &who.email,
        &path,
        &format!("state={rotation_state}"),
    ));
    Ok(redirect_found(&format!("/s/{}", pct_encode(&path))))
}

// ---------------------------------------------------------------------------
// POST /s/{path}/v/{version}/rollback — restore a historical version
// ---------------------------------------------------------------------------

/// `POST /s/{path}/v/{version}/rollback` — copy an existing version to a new latest version.
/// CSRF-checked.
pub async fn rollback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((raw_path, version)): Path<(String, i64)>,
    Form(form): Form<RollbackForm>,
) -> Result<Response, AppError> {
    require_csrf(&headers, &form.csrf_token)?;
    if version < 1 {
        return Err(AppError::BadRequest("Choose a valid version.".to_string()));
    }
    let who = auth::identity(&headers);
    let path = validate_path(&raw_path)?;
    require_read_path(&state, &who, &path).await?;
    let Some(new_version) = state
        .store
        .rollback_secret(&path, version, &who.subject, now_secs())
        .await?
    else {
        return Err(AppError::NotFound("No such version.".to_string()));
    };
    state.audit.emit(AuditEvent::warning(
        "secret.rollback",
        &who.email,
        &path,
        &format!("v{version} -> v{new_version}"),
    ));
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
    require_read_path(&state, &who, &path).await?;

    if !state.store.delete_secret(&path).await? {
        return Err(AppError::NotFound(
            "No secret exists at that path.".to_string(),
        ));
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

async fn readable_secrets(state: &AppState, who: &Identity) -> Result<Vec<SecretMeta>, AppError> {
    let secrets = state.store.list_secrets().await?;
    let mut out = Vec::with_capacity(secrets.len());
    for secret in secrets {
        if state
            .store
            .can_read_secret(&who.subject, &secret.path)
            .await?
        {
            out.push(secret);
        }
    }
    Ok(out)
}

async fn require_read_path(state: &AppState, who: &Identity, path: &str) -> Result<(), AppError> {
    if state.store.can_read_secret(&who.subject, path).await? {
        return Ok(());
    }
    state.audit.emit(AuditEvent::warning(
        "secret.read.denied",
        &who.email,
        path,
        "policy denied",
    ));
    Err(AppError::Forbidden(
        "You do not have read access to that secret path.".to_string(),
    ))
}

/// Seal `value` and append it as a new version of `path`, emitting a `secret.put` audit event.
async fn do_put(
    state: &AppState,
    who: &Identity,
    path: &str,
    value: &str,
) -> Result<i64, AppError> {
    if state.store.get_meta(path).await?.is_some() {
        require_read_path(state, who, path).await?;
    }
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

fn validate_subject(raw: &str) -> Result<String, AppError> {
    let subject = raw.trim();
    if subject.is_empty() {
        return Err(AppError::BadRequest("Enter a subject.".to_string()));
    }
    if subject.chars().count() > MAX_PATH_CHARS {
        return Err(AppError::BadRequest(
            "That subject is too long.".to_string(),
        ));
    }
    if !subject
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '<' | '>' | '"' | '\'' | '&'))
    {
        return Err(AppError::BadRequest(
            "A subject may use printable ASCII except HTML metacharacters.".to_string(),
        ));
    }
    Ok(subject.to_string())
}

fn validate_policy_prefix(raw: &str) -> Result<String, AppError> {
    let prefix = raw.trim();
    if prefix == "*" {
        return Ok(prefix.to_string());
    }
    validate_path(prefix)
}

fn validate_rotation_state(raw: &str) -> Result<String, AppError> {
    match raw.trim() {
        "" | "active" => Ok("active".to_string()),
        "rotation_due" => Ok("rotation_due".to_string()),
        _ => Err(AppError::BadRequest(
            "Choose a valid rotation state.".to_string(),
        )),
    }
}

fn parse_optional_days(raw: &str, label: &str, now: i64) -> Result<Option<i64>, AppError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let days: i64 = raw
        .parse()
        .map_err(|_| AppError::BadRequest(format!("{label} must be a whole number of days.")))?;
    if !(0..=MAX_LIFECYCLE_DAYS).contains(&days) {
        return Err(AppError::BadRequest(format!(
            "{label} must be between 0 and {MAX_LIFECYCLE_DAYS} days."
        )));
    }
    Ok(Some(now + days * 24 * 60 * 60))
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
        return Err(AppError::BadRequest(
            "That secret path is too long.".to_string(),
        ));
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

fn render_index(
    who: &Identity,
    csrf: &str,
    secrets: &[SecretMeta],
    lifecycles: &[SecretLifecycle],
    policies: &[SecretReadPolicy],
    now: i64,
) -> String {
    let count = match secrets.len() {
        1 => "1 secret".to_string(),
        n => format!("{n} secrets"),
    };
    INDEX_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{SHIELD}}", SHIELD_SVG)
        .replace("{{USERBOX}}", &userbox("Vault", Some(&who.email)))
        .replace("{{CSRF}}", &esc(csrf))
        .replace("{{COUNT}}", &esc(&count))
        .replace("{{LIST}}", &render_secret_list(secrets, lifecycles, now))
        .replace("{{DUE_LIST}}", &render_due_list(secrets, lifecycles, now))
        .replace("{{POLICIES}}", &render_policies(policies, csrf))
}

fn render_secret_list(secrets: &[SecretMeta], lifecycles: &[SecretLifecycle], now: i64) -> String {
    if secrets.is_empty() {
        return "<li class=\"secret-item secret-item--empty\">No secrets yet. Add one to get started.</li>".to_string();
    }
    secrets
        .iter()
        .map(|m| {
            let enc = pct_encode(&m.path);
            let lifecycle = lifecycle_for(lifecycles, &m.path);
            let badges = render_lifecycle_badges(lifecycle, now);
            format!(
                "<li class=\"secret-item\">\
                   <div class=\"secret-main\">\
                     <a class=\"secret-path\" href=\"/s/{enc}\">{path}</a>\
                     <div class=\"secret-meta\"><span class=\"badge badge--version\">v{ver}</span>\
                       <span>updated {updated}</span>{badges}</div>\
                   </div>\
                   <span class=\"secret-mask\" aria-hidden=\"true\">{mask}</span>\
                   <a class=\"btn btn-secondary btn-sm\" href=\"/s/{enc}\">Open</a>\
                 </li>",
                enc = esc(&enc),
                path = esc(&m.path),
                ver = m.latest_version,
                updated = esc(&fmt_ts(m.updated_at)),
                badges = badges,
                mask = MASK,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_due_list(secrets: &[SecretMeta], lifecycles: &[SecretLifecycle], now: i64) -> String {
    let mut rows: Vec<(&SecretMeta, &SecretLifecycle)> = secrets
        .iter()
        .filter_map(|m| lifecycle_for(lifecycles, &m.path).map(|l| (m, l)))
        .filter(|(_, l)| lifecycle_is_due_soon(l, now))
        .collect();
    rows.sort_by_key(|(_, l)| next_due_at(l).unwrap_or(i64::MAX));
    if rows.is_empty() {
        return "<li class=\"version-item version-item--empty\">No upcoming expiry or rotation reminders.</li>".to_string();
    }
    rows.iter()
        .map(|(m, l)| {
            let enc = pct_encode(&m.path);
            format!(
                "<li class=\"version-item\">\
                   <div class=\"version-main\"><a class=\"secret-path\" href=\"/s/{enc}\">{path}</a>\
                     <span class=\"version-when\">{badges}</span></div>\
                   <a class=\"btn btn-ghost btn-sm\" href=\"/s/{enc}\">Open</a>\
                 </li>",
                enc = esc(&enc),
                path = esc(&m.path),
                badges = render_lifecycle_badges(Some(l), now),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_policies(policies: &[SecretReadPolicy], csrf: &str) -> String {
    if policies.is_empty() {
        return "<li class=\"version-item version-item--empty\">No read policies. All signed-in admins can read all paths.</li>".to_string();
    }
    policies
        .iter()
        .map(|p| {
            format!(
                "<li class=\"version-item\">\
                   <div class=\"version-main\"><span class=\"version-by\">{subject}</span>\
                     <span class=\"badge\">{prefix}</span>\
                     <span class=\"version-when\">by {by}</span></div>\
                   <form method=\"post\" action=\"/policies/delete\" class=\"inline-form\">\
                     <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                     <input type=\"hidden\" name=\"subject\" value=\"{subject_attr}\">\
                     <input type=\"hidden\" name=\"path_prefix\" value=\"{prefix_attr}\">\
                     <button class=\"btn btn-ghost btn-sm\" type=\"submit\">Remove</button>\
                   </form>\
                 </li>",
                subject = esc(&p.subject),
                prefix = esc(&p.path_prefix),
                by = esc(&p.created_by),
                csrf = esc(csrf),
                subject_attr = esc(&p.subject),
                prefix_attr = esc(&p.path_prefix),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn lifecycle_for<'a>(lifecycles: &'a [SecretLifecycle], path: &str) -> Option<&'a SecretLifecycle> {
    lifecycles.iter().find(|l| l.path == path)
}

fn lifecycle_is_due_soon(lifecycle: &SecretLifecycle, now: i64) -> bool {
    lifecycle.rotation_state == "rotation_due"
        || lifecycle
            .expires_at
            .map(|ts| ts <= now + DUE_HORIZON_SECS)
            .unwrap_or(false)
        || lifecycle
            .rotation_due_at
            .map(|ts| ts <= now + DUE_HORIZON_SECS)
            .unwrap_or(false)
}

/// Fail-closed READ gate: an expired secret must not be decrypted or served. Uses the SAME
/// inclusive `expires_at <= now` boundary as the expired badge (render_lifecycle_badges) so the
/// UI badge and the enforcement gate can never disagree. None lifecycle / None expires_at => not expired.
fn is_expired(lifecycle: Option<&SecretLifecycle>, now: i64) -> bool {
    matches!(lifecycle, Some(lc) if lc.expires_at.map(|ts| ts <= now).unwrap_or(false))
}

fn next_due_at(lifecycle: &SecretLifecycle) -> Option<i64> {
    [lifecycle.expires_at, lifecycle.rotation_due_at]
        .into_iter()
        .flatten()
        .min()
}

fn render_lifecycle_badges(lifecycle: Option<&SecretLifecycle>, now: i64) -> String {
    let Some(lifecycle) = lifecycle else {
        return String::new();
    };
    let mut out = Vec::new();
    if let Some(expires_at) = lifecycle.expires_at {
        let (class, label) = if expires_at <= now {
            ("badge pill-down", "expired")
        } else if expires_at <= now + DUE_HORIZON_SECS {
            ("badge pill-warn", "expires")
        } else {
            ("badge pill-ok", "expires")
        };
        out.push(format!(
            "<span class=\"{class}\">{label} {when}</span>",
            when = esc(&fmt_ts(expires_at))
        ));
    }
    if lifecycle.rotation_state == "rotation_due" {
        out.push("<span class=\"badge pill-warn\">rotation due</span>".to_string());
    } else if let Some(rotation_due_at) = lifecycle.rotation_due_at {
        let (class, label) = if rotation_due_at <= now {
            ("badge pill-warn", "rotate")
        } else if rotation_due_at <= now + DUE_HORIZON_SECS {
            ("badge pill-warn", "rotate")
        } else {
            ("badge", "rotate")
        };
        out.push(format!(
            "<span class=\"{class}\">{label} {when}</span>",
            when = esc(&fmt_ts(rotation_due_at))
        ));
    }
    out.join("")
}

fn lifecycle_summary(lifecycle: Option<&SecretLifecycle>, now: i64) -> String {
    let badges = render_lifecycle_badges(lifecycle, now);
    if badges.is_empty() {
        "No expiry or rotation reminder is set for this secret.".to_string()
    } else {
        badges
    }
}

fn lifecycle_days_value(ts: Option<i64>, now: i64) -> String {
    let Some(ts) = ts else { return String::new() };
    let remaining = ts.saturating_sub(now);
    ((remaining + 86_399) / 86_400).to_string()
}

fn lifecycle_rotation_state(lifecycle: Option<&SecretLifecycle>) -> &str {
    lifecycle
        .map(|l| l.rotation_state.as_str())
        .unwrap_or("active")
}

fn render_detail(
    who: &Identity,
    csrf: &str,
    path: &str,
    latest: &SecretVersion,
    value: Option<&str>,
    history: &[VersionInfo],
    lifecycle: Option<&SecretLifecycle>,
    now: i64,
) -> String {
    let enc = pct_encode(path);
    let value_block = match value {
        Some(v) => render_value_block_live(v),
        None => EXPIRED_VALUE_BLOCK.to_string(),
    };
    SECRET_HTML
        .replace("{{CSS}}", app_css())
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
        // The plaintext exists only in the live value block after the expiry gate has passed.
        .replace("{{VALUE_BLOCK}}", &value_block)
        .replace("{{LIFECYCLE_SUMMARY}}", &lifecycle_summary(lifecycle, now))
        .replace(
            "{{EXPIRES_DAYS}}",
            &lifecycle_days_value(lifecycle.and_then(|l| l.expires_at), now),
        )
        .replace(
            "{{ROTATION_DAYS}}",
            &lifecycle_days_value(lifecycle.and_then(|l| l.rotation_due_at), now),
        )
        .replace(
            "{{ROTATION_ACTIVE_SELECTED}}",
            if lifecycle_rotation_state(lifecycle) == "active" {
                " selected"
            } else {
                ""
            },
        )
        .replace(
            "{{ROTATION_DUE_SELECTED}}",
            if lifecycle_rotation_state(lifecycle) == "rotation_due" {
                " selected"
            } else {
                ""
            },
        )
        .replace("{{HISTORY}}", &render_history(path, history, csrf))
}

const EXPIRED_VALUE_BLOCK: &str = "<div class=\"secret-reveal\"><code class=\"secret-value\" aria-disabled=\"true\">Value withheld — this secret has expired</code></div><p class=\"hint hint--muted\">This secret has expired. Save a new version and clear or extend its expiry below to restore access.</p>";

fn render_value_block_live(value: &str) -> String {
    format!(
        "<div class=\"secret-reveal\">\n          <code class=\"secret-value\" id=\"secretValue\" data-value=\"{value}\" data-mask=\"{mask}\" data-shown=\"false\">{mask}</code>\n          <div class=\"reveal-actions\">\n            <button type=\"button\" class=\"btn btn-secondary btn-sm\" id=\"revealBtn\">Reveal</button>\n            <button type=\"button\" class=\"btn btn-ghost btn-sm\" id=\"copyBtn\">Copy</button>\n          </div>\n        </div>\n        <p class=\"hint hint--muted\">This value was decrypted just now and revealing it was recorded in the audit log. It stays masked until you click Reveal.</p>",
        value = esc(value),
        mask = MASK,
    )
}

fn render_history(path: &str, history: &[VersionInfo], csrf: &str) -> String {
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
                   <div class=\"inline-actions\">\
                     <a class=\"btn btn-ghost btn-sm\" href=\"/s/{enc}/v/{ver}\">Reveal</a>\
                     <form method=\"post\" action=\"/s/{enc}/v/{ver}/rollback\" class=\"inline-form\"\
                           onsubmit=\"return confirm('Rollback to version {ver}? This creates a new latest version.');\">\
                       <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                       <button class=\"btn btn-secondary btn-sm\" type=\"submit\">Rollback</button>\
                     </form>\
                   </div>\
                 </li>",
                ver = v.version,
                when = esc(&fmt_ts(v.created_at)),
                by = esc(&v.created_by),
                enc = esc(&enc),
                csrf = esc(csrf),
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
        .replace("{{CSS}}", app_css())
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
        assert_eq!(
            validate_path(" db/prod/password ").unwrap(),
            "db/prod/password"
        );
        assert_eq!(validate_path("api.key-1").unwrap(), "api.key-1");
    }

    #[test]
    fn path_validation_rejects_bad_paths() {
        for bad in [
            "",
            "/leading",
            "trailing/",
            "a//b",
            "a/../b",
            "has space",
            "ta\tb",
            "uni©de",
        ] {
            assert!(validate_path(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn policy_prefix_accepts_path_or_wildcard() {
        assert_eq!(validate_policy_prefix("*").unwrap(), "*");
        assert_eq!(validate_policy_prefix(" db/prod ").unwrap(), "db/prod");
        assert!(validate_policy_prefix("bad prefix").is_err());
    }

    #[test]
    fn lifecycle_days_are_optional_and_bounded() {
        assert_eq!(parse_optional_days("", "Expiry", 100).unwrap(), None);
        assert_eq!(
            parse_optional_days("2", "Expiry", 100).unwrap(),
            Some(100 + 2 * 24 * 60 * 60)
        );
        assert!(parse_optional_days("-1", "Expiry", 100).is_err());
        assert!(parse_optional_days("3651", "Expiry", 100).is_err());
    }
}
