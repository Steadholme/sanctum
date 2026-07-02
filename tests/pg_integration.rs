//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name sanctum-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=sanctum \
//!   -p 127.0.0.1:55490:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55490/sanctum \
//!   cargo test --test pg_integration -- --nocapture
//! docker rm -f sanctum-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the handlers
//! `.await` sqlx natively with no sync-over-async bridge. The test seals values with a real
//! [`Cipher`] so the round-trip exercises the actual at-rest ciphertext column (the DB only ever
//! holds `base64(nonce || AES-256-GCM)` — never plaintext).

use std::sync::Arc;

use sanctum::crypto::Cipher;
use sanctum::store::{PgStore, Store};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    let cipher = Cipher::new("integration-master-key");

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Raw pool to reset the tables for a clean run + to assert the at-rest invariant.
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secret_lifecycle")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secret_read_policies")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secrets")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secret_meta")
        .execute(&raw)
        .await
        .unwrap();

    let store: Arc<dyn Store> = Arc::new(pg);
    let now = 1_700_000_000i64;

    // --- versioned put + meta tracking -------------------------------------
    let c1 = cipher.seal_secret("db-password-1").unwrap();
    let c2 = cipher.seal_secret("db-password-2").unwrap();
    assert_eq!(
        store
            .put_secret("db/prod/pw", &c1, "alice", now)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .put_secret("db/prod/pw", &c2, "bob", now + 10)
            .await
            .unwrap(),
        2
    );

    let latest = store.get_latest("db/prod/pw").await.unwrap().unwrap();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.created_by, "bob");
    assert_eq!(
        cipher.open_secret(&latest.ciphertext).unwrap(),
        "db-password-2"
    );

    let meta = store.get_meta("db/prod/pw").await.unwrap().unwrap();
    assert_eq!(meta.latest_version, 2);
    assert_eq!(meta.updated_at, now + 10);

    // --- specific version + value-free history (newest-first) --------------
    let v1 = store.get_version("db/prod/pw", 1).await.unwrap().unwrap();
    assert_eq!(cipher.open_secret(&v1.ciphertext).unwrap(), "db-password-1");
    let hist = store.list_versions("db/prod/pw").await.unwrap();
    assert_eq!(
        hist.iter().map(|v| v.version).collect::<Vec<_>>(),
        vec![2, 1]
    );

    // --- rollback copies a historical ciphertext into a new latest version --
    assert_eq!(
        store
            .rollback_secret("db/prod/pw", 1, "carol", now + 15)
            .await
            .unwrap(),
        Some(3)
    );
    let rolled_back = store.get_latest("db/prod/pw").await.unwrap().unwrap();
    assert_eq!(rolled_back.version, 3);
    assert_eq!(rolled_back.created_by, "carol");
    assert_eq!(
        cipher.open_secret(&rolled_back.ciphertext).unwrap(),
        "db-password-1"
    );

    // --- a second path + list (sorted, one row per path) -------------------
    let c3 = cipher.seal_secret("api-token").unwrap();
    store
        .put_secret("api/key", &c3, "alice", now + 20)
        .await
        .unwrap();
    let list = store.list_secrets().await.unwrap();
    assert_eq!(
        list.iter().map(|m| m.path.as_str()).collect::<Vec<_>>(),
        vec!["api/key", "db/prod/pw"]
    );

    // --- lifecycle reminders + read policies ------------------------------
    assert!(store
        .set_lifecycle(
            "db/prod/pw",
            Some(now + 86_400),
            Some(now + 172_800),
            "rotation_due",
            "alice",
            now + 30,
        )
        .await
        .unwrap());
    let lifecycle = store.get_lifecycle("db/prod/pw").await.unwrap().unwrap();
    assert_eq!(lifecycle.expires_at, Some(now + 86_400));
    assert_eq!(lifecycle.rotation_state, "rotation_due");
    assert_eq!(store.list_lifecycle().await.unwrap().len(), 1);

    assert!(store.can_read_secret("bob", "db/prod/pw").await.unwrap());
    store
        .put_read_policy("alice", "db/prod", "admin", now + 40)
        .await
        .unwrap();
    assert!(store.can_read_secret("alice", "db/prod/pw").await.unwrap());
    assert!(!store.can_read_secret("bob", "db/prod/pw").await.unwrap());
    assert_eq!(store.list_read_policies().await.unwrap().len(), 1);

    // --- AT-REST INVARIANT: the ciphertext column never holds plaintext ----
    let row = sqlx::query("SELECT ciphertext FROM secrets WHERE path = $1 AND version = $2")
        .bind("db/prod/pw")
        .bind(3i64)
        .fetch_one(&raw)
        .await
        .unwrap();
    let stored: String = row.try_get("ciphertext").unwrap();
    assert!(
        !stored.contains("db-password-1"),
        "plaintext must never be stored"
    );
    assert_eq!(cipher.open_secret(&stored).unwrap(), "db-password-1");

    // --- delete removes the path + all versions + meta ---------------------
    assert!(store.delete_secret("db/prod/pw").await.unwrap());
    assert!(store.get_latest("db/prod/pw").await.unwrap().is_none());
    assert!(store.list_versions("db/prod/pw").await.unwrap().is_empty());
    assert!(store.get_meta("db/prod/pw").await.unwrap().is_none());
    assert!(store.get_lifecycle("db/prod/pw").await.unwrap().is_none());
    assert!(!store.delete_secret("db/prod/pw").await.unwrap());

    // --- confirm row counts via raw queries (portable SQL path is live) ----
    let n: i64 = sqlx::query("SELECT count(*) AS n FROM secrets")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(n, 1, "only api/key remains after deleting db/prod/pw");

    sqlx::query("DELETE FROM secret_lifecycle")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secret_read_policies")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secrets")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM secret_meta")
        .execute(&raw)
        .await
        .unwrap();
    eprintln!("pg_integration test passed.");
}
