//! Secret storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! magpie/pastefire seam: handlers depend only on the trait, so a FusionDB-backed store can drop
//! in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT, PRIMARY KEY/NOT
//! NULL, parameterized queries, `INSERT .. ON CONFLICT`, a transaction for the versioned put) and
//! runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! The trait is async: the axum handlers `.await` it directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge.
//!
//! Stores deal ONLY in sealed `ciphertext`; encryption/decryption lives entirely in
//! [`crate::crypto`]. A store never sees a plaintext secret value.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{SecretLifecycle, SecretMeta, SecretReadPolicy, SecretVersion, VersionInfo};

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable secret store. Writes are versioned (a put never overwrites an existing version);
/// `delete_secret` removes a path and ALL of its versions.
#[async_trait]
pub trait Store: Send + Sync {
    /// All secret metadata (path + latest version + last-write time), ordered by path. Carries NO
    /// values — backs the list view.
    async fn list_secrets(&self) -> Result<Vec<SecretMeta>, StoreError>;

    /// Append a new version of `path` holding `ciphertext`, returning the new version number.
    /// Computes `latest + 1` and upserts `secret_meta` in one transaction.
    async fn put_secret(
        &self,
        path: &str,
        ciphertext: &str,
        created_by: &str,
        now: i64,
    ) -> Result<i64, StoreError>;

    /// The latest version row for `path` (sealed ciphertext included), or `None`.
    async fn get_latest(&self, path: &str) -> Result<Option<SecretVersion>, StoreError>;

    /// A specific version row for `path` (sealed ciphertext included), or `None`.
    async fn get_version(
        &self,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretVersion>, StoreError>;

    /// Value-free version history for `path`, newest-first.
    async fn list_versions(&self, path: &str) -> Result<Vec<VersionInfo>, StoreError>;

    /// Copy an existing version's sealed ciphertext into a new latest version. Returns the new
    /// version number, or `None` when the source version does not exist.
    async fn rollback_secret(
        &self,
        path: &str,
        version: i64,
        created_by: &str,
        now: i64,
    ) -> Result<Option<i64>, StoreError>;

    /// Metadata for a single `path`, or `None`.
    async fn get_meta(&self, path: &str) -> Result<Option<SecretMeta>, StoreError>;

    /// Optional lifecycle row for a path, or `None`.
    async fn get_lifecycle(&self, path: &str) -> Result<Option<SecretLifecycle>, StoreError>;

    /// All lifecycle rows, ordered by path.
    async fn list_lifecycle(&self) -> Result<Vec<SecretLifecycle>, StoreError>;

    /// Upsert lifecycle controls for an existing path. Returns `false` when the path is absent.
    async fn set_lifecycle(
        &self,
        path: &str,
        expires_at: Option<i64>,
        rotation_due_at: Option<i64>,
        rotation_state: &str,
        updated_by: &str,
        now: i64,
    ) -> Result<bool, StoreError>;

    /// All read policies, ordered by subject then prefix.
    async fn list_read_policies(&self) -> Result<Vec<SecretReadPolicy>, StoreError>;

    /// Upsert one read policy.
    async fn put_read_policy(
        &self,
        subject: &str,
        path_prefix: &str,
        created_by: &str,
        now: i64,
    ) -> Result<(), StoreError>;

    /// Delete one read policy. Returns `true` when it existed.
    async fn delete_read_policy(
        &self,
        subject: &str,
        path_prefix: &str,
    ) -> Result<bool, StoreError>;

    /// Whether `subject` may read `path`. No policies means legacy allow-all.
    async fn can_read_secret(&self, subject: &str, path: &str) -> Result<bool, StoreError>;

    /// Delete `path` and all of its versions. Returns `true` when the secret existed.
    async fn delete_secret(&self, path: &str) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` critical sections are fully synchronous (no `.await`
/// held across the guard), so the std `Mutex` is correct here. Metadata is DERIVED from the
/// version list, so the two stores agree on every `SecretMeta` by construction.
#[derive(Default)]
pub struct InMemoryStore {
    versions: Mutex<Vec<SecretVersion>>,
    lifecycles: Mutex<Vec<SecretLifecycle>>,
    read_policies: Mutex<Vec<SecretReadPolicy>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl InMemoryStore {
    /// Latest version number currently stored for `path` (0 when absent).
    fn latest_version_of(versions: &[SecretVersion], path: &str) -> i64 {
        versions
            .iter()
            .filter(|v| v.path == path)
            .map(|v| v.version)
            .max()
            .unwrap_or(0)
    }

    fn meta_of(versions: &[SecretVersion], path: &str) -> Option<SecretMeta> {
        versions
            .iter()
            .filter(|v| v.path == path)
            .max_by_key(|v| v.version)
            .map(|v| SecretMeta {
                path: v.path.clone(),
                latest_version: v.version,
                updated_at: v.created_at,
            })
    }

    fn policy_allows(policies: &[SecretReadPolicy], subject: &str, path: &str) -> bool {
        policies.is_empty()
            || policies
                .iter()
                .any(|p| p.subject == subject && path_matches_prefix(path, &p.path_prefix))
    }
}

/// Path-prefix policy matching. `db/prod` matches `db/prod` and `db/prod/password`, but not
/// `db/production`. `*` grants all paths to that subject.
pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    prefix == "*"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .map(|rest| rest.starts_with('/'))
            .unwrap_or(false)
}

#[async_trait]
impl Store for InMemoryStore {
    async fn list_secrets(&self) -> Result<Vec<SecretMeta>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        let mut paths: Vec<String> = versions.iter().map(|v| v.path.clone()).collect();
        paths.sort();
        paths.dedup();
        let mut out: Vec<SecretMeta> = paths
            .iter()
            .filter_map(|p| Self::meta_of(&versions, p))
            .collect();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    async fn put_secret(
        &self,
        path: &str,
        ciphertext: &str,
        created_by: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let next = Self::latest_version_of(&versions, path) + 1;
        versions.push(SecretVersion {
            path: path.to_string(),
            version: next,
            ciphertext: ciphertext.to_string(),
            created_at: now,
            created_by: created_by.to_string(),
        });
        Ok(next)
    }

    async fn get_latest(&self, path: &str) -> Result<Option<SecretVersion>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        Ok(versions
            .iter()
            .filter(|v| v.path == path)
            .max_by_key(|v| v.version)
            .cloned())
    }

    async fn get_version(
        &self,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretVersion>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        Ok(versions
            .iter()
            .find(|v| v.path == path && v.version == version)
            .cloned())
    }

    async fn list_versions(&self, path: &str) -> Result<Vec<VersionInfo>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        let mut out: Vec<VersionInfo> = versions
            .iter()
            .filter(|v| v.path == path)
            .map(|v| VersionInfo {
                version: v.version,
                created_at: v.created_at,
                created_by: v.created_by.clone(),
            })
            .collect();
        out.sort_by_key(|v| std::cmp::Reverse(v.version));
        Ok(out)
    }

    async fn rollback_secret(
        &self,
        path: &str,
        version: i64,
        created_by: &str,
        now: i64,
    ) -> Result<Option<i64>, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let Some(source) = versions
            .iter()
            .find(|v| v.path == path && v.version == version)
            .cloned()
        else {
            return Ok(None);
        };
        let next = Self::latest_version_of(&versions, path) + 1;
        versions.push(SecretVersion {
            path: path.to_string(),
            version: next,
            ciphertext: source.ciphertext,
            created_at: now,
            created_by: created_by.to_string(),
        });
        Ok(Some(next))
    }

    async fn get_meta(&self, path: &str) -> Result<Option<SecretMeta>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        Ok(Self::meta_of(&versions, path))
    }

    async fn get_lifecycle(&self, path: &str) -> Result<Option<SecretLifecycle>, StoreError> {
        let lifecycles = self.lifecycles.lock().expect("lifecycles lock poisoned");
        Ok(lifecycles.iter().find(|l| l.path == path).cloned())
    }

    async fn list_lifecycle(&self) -> Result<Vec<SecretLifecycle>, StoreError> {
        let lifecycles = self.lifecycles.lock().expect("lifecycles lock poisoned");
        let mut out = lifecycles.clone();
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    async fn set_lifecycle(
        &self,
        path: &str,
        expires_at: Option<i64>,
        rotation_due_at: Option<i64>,
        rotation_state: &str,
        updated_by: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        {
            let versions = self.versions.lock().expect("versions lock poisoned");
            if Self::meta_of(&versions, path).is_none() {
                return Ok(false);
            }
        }
        let mut lifecycles = self.lifecycles.lock().expect("lifecycles lock poisoned");
        let row = SecretLifecycle {
            path: path.to_string(),
            expires_at,
            rotation_due_at,
            rotation_state: rotation_state.to_string(),
            updated_at: now,
            updated_by: updated_by.to_string(),
        };
        match lifecycles.iter_mut().find(|l| l.path == path) {
            Some(existing) => *existing = row,
            None => lifecycles.push(row),
        }
        Ok(true)
    }

    async fn list_read_policies(&self) -> Result<Vec<SecretReadPolicy>, StoreError> {
        let policies = self
            .read_policies
            .lock()
            .expect("read_policies lock poisoned");
        let mut out = policies.clone();
        out.sort_by(|a, b| {
            a.subject
                .cmp(&b.subject)
                .then(a.path_prefix.cmp(&b.path_prefix))
        });
        Ok(out)
    }

    async fn put_read_policy(
        &self,
        subject: &str,
        path_prefix: &str,
        created_by: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut policies = self
            .read_policies
            .lock()
            .expect("read_policies lock poisoned");
        let row = SecretReadPolicy {
            subject: subject.to_string(),
            path_prefix: path_prefix.to_string(),
            created_at: now,
            created_by: created_by.to_string(),
        };
        match policies
            .iter_mut()
            .find(|p| p.subject == subject && p.path_prefix == path_prefix)
        {
            Some(existing) => *existing = row,
            None => policies.push(row),
        }
        Ok(())
    }

    async fn delete_read_policy(
        &self,
        subject: &str,
        path_prefix: &str,
    ) -> Result<bool, StoreError> {
        let mut policies = self
            .read_policies
            .lock()
            .expect("read_policies lock poisoned");
        let before = policies.len();
        policies.retain(|p| !(p.subject == subject && p.path_prefix == path_prefix));
        Ok(policies.len() != before)
    }

    async fn can_read_secret(&self, subject: &str, path: &str) -> Result<bool, StoreError> {
        let policies = self
            .read_policies
            .lock()
            .expect("read_policies lock poisoned");
        Ok(Self::policy_allows(&policies, subject, path))
    }

    async fn delete_secret(&self, path: &str) -> Result<bool, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let before = versions.len();
        versions.retain(|v| v.path != path);
        self.lifecycles
            .lock()
            .expect("lifecycles lock poisoned")
            .retain(|l| l.path != path);
        Ok(versions.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `SANCTUM_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a query never blocks a worker thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds a pooled connection; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS secrets (\
                 path TEXT NOT NULL, \
                 version BIGINT NOT NULL, \
                 ciphertext TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 created_by TEXT NOT NULL, \
                 PRIMARY KEY (path, version)\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS secret_meta (\
                 path TEXT PRIMARY KEY, \
                 latest_version BIGINT NOT NULL, \
                 updated_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS secret_lifecycle (\
                 path TEXT PRIMARY KEY, \
                 expires_at BIGINT, \
                 rotation_due_at BIGINT, \
                 rotation_state TEXT NOT NULL, \
                 updated_at BIGINT NOT NULL, \
                 updated_by TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS secret_read_policies (\
                 subject TEXT NOT NULL, \
                 path_prefix TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 created_by TEXT NOT NULL, \
                 PRIMARY KEY (subject, path_prefix)\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn version_from_row(row: &sqlx::postgres::PgRow) -> Result<SecretVersion, sqlx::Error> {
        Ok(SecretVersion {
            path: row.try_get("path")?,
            version: row.try_get("version")?,
            ciphertext: row.try_get("ciphertext")?,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
        })
    }

    fn lifecycle_from_row(row: &sqlx::postgres::PgRow) -> Result<SecretLifecycle, sqlx::Error> {
        Ok(SecretLifecycle {
            path: row.try_get("path")?,
            expires_at: row.try_get("expires_at")?,
            rotation_due_at: row.try_get("rotation_due_at")?,
            rotation_state: row.try_get("rotation_state")?,
            updated_at: row.try_get("updated_at")?,
            updated_by: row.try_get("updated_by")?,
        })
    }

    fn read_policy_from_row(row: &sqlx::postgres::PgRow) -> Result<SecretReadPolicy, sqlx::Error> {
        Ok(SecretReadPolicy {
            subject: row.try_get("subject")?,
            path_prefix: row.try_get("path_prefix")?,
            created_at: row.try_get("created_at")?,
            created_by: row.try_get("created_by")?,
        })
    }

    async fn list_secrets_async(&self) -> Result<Vec<SecretMeta>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT path, latest_version, updated_at FROM secret_meta ORDER BY path ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(SecretMeta {
                    path: r.try_get("path")?,
                    latest_version: r.try_get("latest_version")?,
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect()
    }

    async fn put_secret_async(
        &self,
        path: &str,
        ciphertext: &str,
        created_by: &str,
        now: i64,
    ) -> Result<i64, sqlx::Error> {
        // One transaction: compute the next version from the live MAX, insert the immutable
        // version row, then upsert the meta pointer. Standard SQL throughout.
        let mut tx = self.pool.begin().await?;
        let next: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) + 1 FROM secrets WHERE path = $1")
                .bind(path)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query(
            "INSERT INTO secrets (path, version, ciphertext, created_at, created_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(path)
        .bind(next)
        .bind(ciphertext)
        .bind(now)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO secret_meta (path, latest_version, updated_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (path) DO UPDATE SET latest_version = $2, updated_at = $3",
        )
        .bind(path)
        .bind(next)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(next)
    }

    async fn get_latest_async(&self, path: &str) -> Result<Option<SecretVersion>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT path, version, ciphertext, created_at, created_by FROM secrets \
             WHERE path = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::version_from_row).transpose()
    }

    async fn get_version_async(
        &self,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretVersion>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT path, version, ciphertext, created_at, created_by FROM secrets \
             WHERE path = $1 AND version = $2",
        )
        .bind(path)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::version_from_row).transpose()
    }

    async fn list_versions_async(&self, path: &str) -> Result<Vec<VersionInfo>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT version, created_at, created_by FROM secrets \
             WHERE path = $1 ORDER BY version DESC",
        )
        .bind(path)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(VersionInfo {
                    version: r.try_get("version")?,
                    created_at: r.try_get("created_at")?,
                    created_by: r.try_get("created_by")?,
                })
            })
            .collect()
    }

    async fn rollback_secret_async(
        &self,
        path: &str,
        version: i64,
        created_by: &str,
        now: i64,
    ) -> Result<Option<i64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let source: Option<String> =
            sqlx::query_scalar("SELECT ciphertext FROM secrets WHERE path = $1 AND version = $2")
                .bind(path)
                .bind(version)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(ciphertext) = source else {
            tx.rollback().await?;
            return Ok(None);
        };
        let next: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) + 1 FROM secrets WHERE path = $1")
                .bind(path)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query(
            "INSERT INTO secrets (path, version, ciphertext, created_at, created_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(path)
        .bind(next)
        .bind(ciphertext)
        .bind(now)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO secret_meta (path, latest_version, updated_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (path) DO UPDATE SET latest_version = $2, updated_at = $3",
        )
        .bind(path)
        .bind(next)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(next))
    }

    async fn get_meta_async(&self, path: &str) -> Result<Option<SecretMeta>, sqlx::Error> {
        let row =
            sqlx::query("SELECT path, latest_version, updated_at FROM secret_meta WHERE path = $1")
                .bind(path)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some(r) => Ok(Some(SecretMeta {
                path: r.try_get("path")?,
                latest_version: r.try_get("latest_version")?,
                updated_at: r.try_get("updated_at")?,
            })),
            None => Ok(None),
        }
    }

    async fn get_lifecycle_async(
        &self,
        path: &str,
    ) -> Result<Option<SecretLifecycle>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT path, expires_at, rotation_due_at, rotation_state, updated_at, updated_by \
             FROM secret_lifecycle WHERE path = $1",
        )
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::lifecycle_from_row).transpose()
    }

    async fn list_lifecycle_async(&self) -> Result<Vec<SecretLifecycle>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT path, expires_at, rotation_due_at, rotation_state, updated_at, updated_by \
             FROM secret_lifecycle ORDER BY path ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::lifecycle_from_row).collect()
    }

    async fn set_lifecycle_async(
        &self,
        path: &str,
        expires_at: Option<i64>,
        rotation_due_at: Option<i64>,
        rotation_state: &str,
        updated_by: &str,
        now: i64,
    ) -> Result<bool, sqlx::Error> {
        if self.get_meta_async(path).await?.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO secret_lifecycle \
             (path, expires_at, rotation_due_at, rotation_state, updated_at, updated_by) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (path) DO UPDATE SET \
               expires_at = $2, rotation_due_at = $3, rotation_state = $4, \
               updated_at = $5, updated_by = $6",
        )
        .bind(path)
        .bind(expires_at)
        .bind(rotation_due_at)
        .bind(rotation_state)
        .bind(now)
        .bind(updated_by)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    async fn list_read_policies_async(&self) -> Result<Vec<SecretReadPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT subject, path_prefix, created_at, created_by FROM secret_read_policies \
             ORDER BY subject ASC, path_prefix ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::read_policy_from_row).collect()
    }

    async fn put_read_policy_async(
        &self,
        subject: &str,
        path_prefix: &str,
        created_by: &str,
        now: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO secret_read_policies (subject, path_prefix, created_at, created_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (subject, path_prefix) DO UPDATE SET created_at = $3, created_by = $4",
        )
        .bind(subject)
        .bind(path_prefix)
        .bind(now)
        .bind(created_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_read_policy_async(
        &self,
        subject: &str,
        path_prefix: &str,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM secret_read_policies WHERE subject = $1 AND path_prefix = $2")
                .bind(subject)
                .bind(path_prefix)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn can_read_secret_async(&self, subject: &str, path: &str) -> Result<bool, sqlx::Error> {
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM secret_read_policies")
            .fetch_one(&self.pool)
            .await?;
        if total == 0 {
            return Ok(true);
        }
        let rows = sqlx::query("SELECT path_prefix FROM secret_read_policies WHERE subject = $1")
            .bind(subject)
            .fetch_all(&self.pool)
            .await?;
        for row in rows {
            let prefix: String = row.try_get("path_prefix")?;
            if path_matches_prefix(path, &prefix) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_secret_async(&self, path: &str) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM secrets WHERE path = $1")
            .bind(path)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM secret_lifecycle WHERE path = $1")
            .bind(path)
            .execute(&mut *tx)
            .await?;
        let meta = sqlx::query("DELETE FROM secret_meta WHERE path = $1")
            .bind(path)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(meta.rows_affected() > 0)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_secrets(&self) -> Result<Vec<SecretMeta>, StoreError> {
        self.list_secrets_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn put_secret(
        &self,
        path: &str,
        ciphertext: &str,
        created_by: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        self.put_secret_async(path, ciphertext, created_by, now)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_latest(&self, path: &str) -> Result<Option<SecretVersion>, StoreError> {
        self.get_latest_async(path)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_version(
        &self,
        path: &str,
        version: i64,
    ) -> Result<Option<SecretVersion>, StoreError> {
        self.get_version_async(path, version)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_versions(&self, path: &str) -> Result<Vec<VersionInfo>, StoreError> {
        self.list_versions_async(path)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn rollback_secret(
        &self,
        path: &str,
        version: i64,
        created_by: &str,
        now: i64,
    ) -> Result<Option<i64>, StoreError> {
        self.rollback_secret_async(path, version, created_by, now)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_meta(&self, path: &str) -> Result<Option<SecretMeta>, StoreError> {
        self.get_meta_async(path)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_lifecycle(&self, path: &str) -> Result<Option<SecretLifecycle>, StoreError> {
        self.get_lifecycle_async(path)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_lifecycle(&self) -> Result<Vec<SecretLifecycle>, StoreError> {
        self.list_lifecycle_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn set_lifecycle(
        &self,
        path: &str,
        expires_at: Option<i64>,
        rotation_due_at: Option<i64>,
        rotation_state: &str,
        updated_by: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.set_lifecycle_async(
            path,
            expires_at,
            rotation_due_at,
            rotation_state,
            updated_by,
            now,
        )
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_read_policies(&self) -> Result<Vec<SecretReadPolicy>, StoreError> {
        self.list_read_policies_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn put_read_policy(
        &self,
        subject: &str,
        path_prefix: &str,
        created_by: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.put_read_policy_async(subject, path_prefix, created_by, now)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_read_policy(
        &self,
        subject: &str,
        path_prefix: &str,
    ) -> Result<bool, StoreError> {
        self.delete_read_policy_async(subject, path_prefix)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn can_read_secret(&self, subject: &str, path: &str) -> Result<bool, StoreError> {
        self.can_read_secret_async(subject, path)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_secret(&self, path: &str) -> Result<bool, StoreError> {
        self.delete_secret_async(path)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_is_versioned_and_meta_tracks_latest() {
        let s = InMemoryStore::new();
        assert_eq!(s.put_secret("db/pw", "c1", "alice", 10).await.unwrap(), 1);
        assert_eq!(s.put_secret("db/pw", "c2", "alice", 20).await.unwrap(), 2);
        assert_eq!(s.put_secret("db/pw", "c3", "bob", 30).await.unwrap(), 3);

        let latest = s.get_latest("db/pw").await.unwrap().unwrap();
        assert_eq!(latest.version, 3);
        assert_eq!(latest.ciphertext, "c3");
        assert_eq!(latest.created_by, "bob");

        let meta = s.get_meta("db/pw").await.unwrap().unwrap();
        assert_eq!(meta.latest_version, 3);
        assert_eq!(meta.updated_at, 30);
    }

    #[tokio::test]
    async fn history_is_newest_first_and_value_free() {
        let s = InMemoryStore::new();
        s.put_secret("k", "c1", "u", 10).await.unwrap();
        s.put_secret("k", "c2", "u", 20).await.unwrap();
        let hist = s.list_versions("k").await.unwrap();
        assert_eq!(
            hist.iter().map(|v| v.version).collect::<Vec<_>>(),
            vec![2, 1]
        );

        let v1 = s.get_version("k", 1).await.unwrap().unwrap();
        assert_eq!(v1.ciphertext, "c1");
        assert!(s.get_version("k", 99).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_is_sorted_and_one_row_per_path() {
        let s = InMemoryStore::new();
        s.put_secret("zeta", "c", "u", 1).await.unwrap();
        s.put_secret("alpha", "c", "u", 1).await.unwrap();
        s.put_secret("alpha", "c", "u", 2).await.unwrap();
        let list = s.list_secrets().await.unwrap();
        assert_eq!(
            list.iter().map(|m| m.path.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        assert_eq!(list[0].latest_version, 2);
    }

    #[tokio::test]
    async fn delete_removes_all_versions() {
        let s = InMemoryStore::new();
        s.put_secret("k", "c1", "u", 1).await.unwrap();
        s.put_secret("k", "c2", "u", 2).await.unwrap();
        s.set_lifecycle("k", Some(100), Some(200), "active", "u", 3)
            .await
            .unwrap();
        assert!(s.delete_secret("k").await.unwrap());
        assert!(s.get_latest("k").await.unwrap().is_none());
        assert!(s.list_versions("k").await.unwrap().is_empty());
        assert!(s.get_lifecycle("k").await.unwrap().is_none());
        assert!(!s.delete_secret("k").await.unwrap());
    }

    #[tokio::test]
    async fn rollback_copies_existing_ciphertext_to_new_latest() {
        let s = InMemoryStore::new();
        s.put_secret("k", "c1", "alice", 10).await.unwrap();
        s.put_secret("k", "c2", "alice", 20).await.unwrap();
        assert_eq!(s.rollback_secret("k", 1, "bob", 30).await.unwrap(), Some(3));

        let latest = s.get_latest("k").await.unwrap().unwrap();
        assert_eq!(latest.version, 3);
        assert_eq!(latest.ciphertext, "c1");
        assert_eq!(latest.created_by, "bob");
        assert_eq!(s.rollback_secret("k", 99, "bob", 40).await.unwrap(), None);
    }

    #[tokio::test]
    async fn lifecycle_requires_existing_path_and_is_upserted() {
        let s = InMemoryStore::new();
        assert!(!s
            .set_lifecycle("missing", Some(100), None, "active", "u", 1)
            .await
            .unwrap());
        s.put_secret("k", "c", "u", 10).await.unwrap();
        assert!(s
            .set_lifecycle("k", Some(100), Some(200), "active", "u", 20)
            .await
            .unwrap());
        assert!(s
            .set_lifecycle("k", None, Some(300), "rotation_due", "u2", 30)
            .await
            .unwrap());
        let lifecycle = s.get_lifecycle("k").await.unwrap().unwrap();
        assert_eq!(lifecycle.expires_at, None);
        assert_eq!(lifecycle.rotation_due_at, Some(300));
        assert_eq!(lifecycle.rotation_state, "rotation_due");
        assert_eq!(s.list_lifecycle().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn read_policies_default_allow_then_restrict_by_prefix() {
        let s = InMemoryStore::new();
        assert!(s.can_read_secret("alice", "db/prod/pw").await.unwrap());

        s.put_read_policy("alice", "db/prod", "admin", 10)
            .await
            .unwrap();
        assert!(s.can_read_secret("alice", "db/prod/pw").await.unwrap());
        assert!(s.can_read_secret("alice", "db/prod").await.unwrap());
        assert!(!s.can_read_secret("alice", "db/production").await.unwrap());
        assert!(!s.can_read_secret("bob", "db/prod/pw").await.unwrap());

        s.put_read_policy("bob", "*", "admin", 20).await.unwrap();
        assert!(s.can_read_secret("bob", "anything/here").await.unwrap());
        assert!(s.delete_read_policy("bob", "*").await.unwrap());
        assert!(!s.delete_read_policy("bob", "*").await.unwrap());
    }

    #[test]
    fn path_prefix_matching_is_segment_aware() {
        assert!(path_matches_prefix("db/prod/pw", "db/prod"));
        assert!(path_matches_prefix("db/prod", "db/prod"));
        assert!(path_matches_prefix("db/prod/pw", "*"));
        assert!(!path_matches_prefix("db/production", "db/prod"));
    }
}
