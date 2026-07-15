//! Internal transit API: `POST /transit/encrypt` and `POST /transit/decrypt`.
//!
//! These are JSON, service-to-service endpoints (NOT browser pages), so they render compact JSON
//! envelopes and JSON errors — never the HTML error page. They let OTHER Steadholme services encrypt
//! /decrypt payloads under a NAMED transit key WITHOUT holding the master key themselves.
//!
//! Authorization (see [`crate::auth::transit_authorized`]) accepts EITHER the gateway-injected SSO
//! identity (an admin testing through Sluice) OR a `Authorization: Bearer <TRANSIT_TOKEN>` for
//! in-network callers that reach Sanctum directly on the `holdfast` network. For v1 these routes
//! live under the same (SSO-fronted) app and additionally honor the internal token mode.
//!
//! Ciphertext is the self-describing `sanctum:v1:{key}:{base64blob}` token: `/transit/decrypt`
//! recovers the key name from the token, so a caller never has to track which key sealed what.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth;
use crate::AppState;

/// `{ "plaintext": "...", "key": "optional-key-name" }`. When `key` is omitted, the configured
/// default transit key is used.
#[derive(Debug, Deserialize)]
pub struct EncryptReq {
    #[serde(default)]
    pub plaintext: String,
    #[serde(default)]
    pub key: Option<String>,
}

/// `{ "ciphertext": "sanctum:v1:...", "key": "..." }`.
#[derive(Debug, Serialize)]
pub struct EncryptResp {
    pub ciphertext: String,
    pub key: String,
}

/// `{ "ciphertext": "sanctum:v1:..." }`.
#[derive(Debug, Deserialize)]
pub struct DecryptReq {
    #[serde(default)]
    pub ciphertext: String,
}

/// `{ "plaintext": "..." }`.
#[derive(Debug, Serialize)]
pub struct DecryptResp {
    pub plaintext: String,
}

/// `POST /transit/encrypt` — seal `plaintext` under the named (or default) transit key.
pub async fn encrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EncryptReq>,
) -> Response {
    if !auth::transit_authorized(&headers, state.config.transit_token.as_deref()) {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let key = req
        .key
        .filter(|k| !k.trim().is_empty())
        .unwrap_or_else(|| state.config.default_transit_key.clone());
    match state.cipher.transit_encrypt(&key, &req.plaintext) {
        Ok(ciphertext) => (StatusCode::OK, Json(EncryptResp { ciphertext, key })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

/// `POST /transit/decrypt` — open a `sanctum:v1:{key}:...` token back to its plaintext.
pub async fn decrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DecryptReq>,
) -> Response {
    if !auth::transit_authorized(&headers, state.config.transit_token.as_deref()) {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match state.cipher.transit_decrypt(req.ciphertext.trim()) {
        Ok(plaintext) => (StatusCode::OK, Json(DecryptResp { plaintext })).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

/// A compact JSON error envelope: `{ "error": "..." }`.
fn json_err(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}
