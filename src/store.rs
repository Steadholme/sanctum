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

use crate::model::{SecretMeta, SecretVersion, VersionInfo};

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
    async fn get_version(&self, path: &str, version: i64)
        -> Result<Option<SecretVersion>, StoreError>;

    /// Value-free version history for `path`, newest-first.
    async fn list_versions(&self, path: &str) -> Result<Vec<VersionInfo>, StoreError>;

    /// Metadata for a single `path`, or `None`.
    async fn get_meta(&self, path: &str) -> Result<Option<SecretMeta>, StoreError>;

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

    async fn get_meta(&self, path: &str) -> Result<Option<SecretMeta>, StoreError> {
        let versions = self.versions.lock().expect("versions lock poisoned");
        Ok(Self::meta_of(&versions, path))
    }

    async fn delete_secret(&self, path: &str) -> Result<bool, StoreError> {
        let mut versions = self.versions.lock().expect("versions lock poisoned");
        let before = versions.len();
        versions.retain(|v| v.path != path);
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

    async fn get_meta_async(&self, path: &str) -> Result<Option<SecretMeta>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT path, latest_version, updated_at FROM secret_meta WHERE path = $1",
        )
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

    async fn delete_secret_async(&self, path: &str) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM secrets WHERE path = $1")
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

    async fn get_meta(&self, path: &str) -> Result<Option<SecretMeta>, StoreError> {
        self.get_meta_async(path)
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
        assert_eq!(hist.iter().map(|v| v.version).collect::<Vec<_>>(), vec![2, 1]);

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
        assert!(s.delete_secret("k").await.unwrap());
        assert!(s.get_latest("k").await.unwrap().is_none());
        assert!(s.list_versions("k").await.unwrap().is_empty());
        assert!(!s.delete_secret("k").await.unwrap());
    }
}
