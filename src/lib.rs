//! Sanctum — personal secrets vault for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store + dev master key, no database) and
//! [`build_state_from_env`] (env-selected store + real `MASTER_KEY` + Watchtower audit).
//! Integration tests consume [`app`] directly via `tower::oneshot`.
//!
//! Endpoints (served at the subdomain ROOT — Sluice forwards the path unmodified):
//! - `GET  /healthz`               — liveness (public)
//! - `GET  /`                      — list secret paths + latest versions (NO values)
//! - `POST /`                      — create/update a secret (path + value) -> 302 detail (CSRF)
//! - `POST /policies`              — add/update a read policy (CSRF)
//! - `POST /policies/delete`       — remove a read policy (CSRF)
//! - `GET  /s/{path}`              — reveal the latest value (AUDITED) + version history
//! - `POST /s/{path}`              — put a new version -> 302 detail (CSRF)
//! - `POST /s/{path}/lifecycle`    — set expiry / rotation reminders (CSRF)
//! - `POST /s/{path}/delete`       — delete the path + all versions -> 302 `/` (CSRF)
//! - `GET  /s/{path}/v/{version}`  — reveal a specific historical version (AUDITED)
//! - `POST /s/{path}/v/{version}/rollback` — copy that version to a new latest version (CSRF)
//! - `POST /transit/encrypt`       — seal a payload under a named transit key (token OR SSO)
//! - `POST /transit/decrypt`       — open a `sanctum:v1:...` token (token OR SSO)
//!
//! Secret VALUES are AES-256-GCM at rest (see [`crypto`]); the plaintext is never stored or logged.

pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod error;
pub mod handlers;
pub mod model;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::crypto::Cipher;
use crate::store::{InMemoryStore, PgStore, Store};

/// Built-in DEV master key — used ONLY by [`build_dev_state`] and the in-memory dev fallback. The
/// postgres path REFUSES to start without a real `MASTER_KEY`, so production never rides this.
pub const DEV_MASTER_KEY: &str = "sanctum-dev-master-key-do-not-use-in-production";

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub cipher: Arc<Cipher>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`. Routes are explicit (no fallback): the
/// service owns its subdomain, so Sluice forwards these exact paths.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route(
            "/",
            get(handlers::secrets::index).post(handlers::secrets::create),
        )
        .route("/policies", post(handlers::secrets::add_policy))
        .route("/policies/delete", post(handlers::secrets::delete_policy))
        .route(
            "/s/{path}",
            get(handlers::secrets::reveal).post(handlers::secrets::put),
        )
        .route("/s/{path}/lifecycle", post(handlers::secrets::lifecycle))
        .route("/s/{path}/delete", post(handlers::secrets::delete))
        .route(
            "/s/{path}/v/{version}",
            get(handlers::secrets::reveal_version),
        )
        .route(
            "/s/{path}/v/{version}/rollback",
            post(handlers::secrets::rollback),
        )
        .route("/transit/encrypt", post(handlers::transit::encrypt))
        .route("/transit/decrypt", post(handlers::transit::decrypt))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], the DEV-key [`Cipher`], and a
/// disabled audit sink (no network). Tests reuse this shape and swap in their own pieces.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        cipher: Arc::new(Cipher::new(DEV_MASTER_KEY)),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// The store is selected by `SANCTUM_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`]; REQUIRES a
///   non-empty `MASTER_KEY` (the vault must never persist ciphertext under the dev key).
///
/// The cipher derives its keys from `MASTER_KEY` (falling back to the DEV key only for the memory
/// store, with a warning). The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` +
/// `AUDIT_INGEST_TOKEN`. Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();
    let store_kind = env_nonempty("SANCTUM_STORE").unwrap_or_else(|| "memory".to_string());
    let master = env_nonempty("MASTER_KEY");

    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "SANCTUM_STORE=postgres requires DATABASE_URL".to_string())?;
            if master.is_none() {
                return Err(
                    "SANCTUM_STORE=postgres requires MASTER_KEY (refusing to persist ciphertext \
                     under the dev key)"
                        .to_string(),
                );
            }
            tracing::info!("SANCTUM_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => {
            return Err(format!(
                "unknown SANCTUM_STORE={other} (use memory|postgres)"
            ))
        }
    };

    let cipher = match master {
        Some(m) => Arc::new(Cipher::new(&m)),
        None => {
            tracing::warn!(
                "MASTER_KEY unset — using the built-in DEV master key (memory store only)"
            );
            Arc::new(Cipher::new(DEV_MASTER_KEY))
        }
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        cipher,
        audit,
    })
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Current wall-clock time in epoch seconds (`created_at` / `updated_at` granularity).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Generate a random URL-safe alphanumeric string of `len` characters from a 62-symbol alphabet,
/// via the OS CSPRNG. Used for the double-submit CSRF token. The modulo over 62 introduces a
/// negligible bias that is irrelevant for tokens of this size.
pub fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}
