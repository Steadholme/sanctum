//! Application errors for the management UI, rendered as branded HTML pages.
//!
//! The SSO vault surface is browser-facing, so a failure renders the enterprise error page (the
//! shared app-bar + design tokens) rather than a JSON envelope. The transit API renders its own
//! compact JSON errors (see [`crate::handlers::transit`]). Store failures collapse to a 500; a
//! missing path is a 404; a bad path / CSRF mismatch is a 400; a decrypt failure is a 500 (the
//! ciphertext at rest is unreadable — never leak why).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/rejected request (e.g. CSRF mismatch, invalid path/value).
    #[error("bad_request: {0}")]
    BadRequest(String),

    /// Authenticated but not allowed.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such secret / version.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Unexpected internal failure (store I/O, or an unreadable ciphertext at rest).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    /// Map to `(status, heading, message)` for the rendered error page.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::BadRequest(d) => (StatusCode::BAD_REQUEST, "Request rejected", d.clone()),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, "Not allowed", d.clone()),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                d.clone(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

/// Store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}

/// A crypto failure during a UI reveal/put is a 500: the value at rest is unreadable (wrong master
/// key, corruption, or tampering). The coarse message never reveals which.
impl From<crate::crypto::CryptoError> for AppError {
    fn from(_e: crate::crypto::CryptoError) -> Self {
        AppError::Internal("This secret could not be decrypted with the current master key.".to_string())
    }
}
