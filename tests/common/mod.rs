//! Shared harness for the integration tests.
//!
//! The tests need a real Postgres because the point of them is that the schema,
//! the upserts and the partial unique indexes behave as designed. Set
//! `NETGRASP_TEST_DATABASE_URL` to point somewhere else; the default is a local
//! `netgrasp` database.
//!
//! When no database is reachable the harness returns `None` and the test prints
//! why and passes. A developer without Postgres running should still get a green
//! `cargo test` on everything else, and CI sets the variable so the coverage is
//! not quietly lost there.

use netgraspd::db::Db;

use tokio::sync::{Mutex, MutexGuard};

/// Default connection for a local development database.
const DEFAULT_URL: &str = "postgres://netgrasp:netgrasp@localhost:5432/netgrasp";

/// Serialises the integration tests.
///
/// They share one database and each starts by truncating it, so running two at
/// once would have them delete each other's fixtures. Holding the lock for the
/// whole test is simpler and more honest than trying to make them independent.
static DB_LOCK: Mutex<()> = Mutex::const_new(());

/// A migrated, empty database, held exclusively for the duration of a test.
pub struct TestDb {
    /// The pool under test.
    pub db: Db,
    _guard: MutexGuard<'static, ()>,
}

impl TestDb {
    /// Checks out a pooled connection.
    pub async fn client(&self) -> deadpool_postgres::Client {
        self.db.client().await.expect("a pooled connection")
    }

    /// Counts rows in one of the `ng_*` tables.
    pub async fn count(&self, table: &str) -> i64 {
        let client = self.client().await;
        let row = client
            .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .await
            .unwrap_or_else(|err| panic!("counting {table}: {err}"));
        row.get(0)
    }

    /// Runs a scalar query returning one `i64`.
    pub async fn scalar(&self, sql: &str) -> i64 {
        let client = self.client().await;
        let row = client
            .query_one(sql, &[])
            .await
            .unwrap_or_else(|err| panic!("running {sql:?}: {err}"));
        row.get(0)
    }
}

/// Connects, migrates and empties the test database.
///
/// Returns `None` when no database is reachable, so the caller can skip.
pub async fn test_db() -> Option<TestDb> {
    let guard = DB_LOCK.lock().await;
    let url =
        std::env::var("NETGRASP_TEST_DATABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());

    let cfg = netgraspd::config::DatabaseConfig {
        url: url.clone(),
        pool_size: 4,
    };
    let db = Db::connect(&cfg).expect("a valid test connection URL");
    if db.client().await.is_err() {
        eprintln!("skipping: no Postgres at {url}");
        return None;
    }
    if let Err(err) = Db::migrate(&url).await {
        eprintln!("skipping: could not migrate {url}: {err}");
        return None;
    }

    {
        let client = db.client().await.expect("a pooled connection");
        client
            .batch_execute(
                "TRUNCATE ng_events, ng_ip_history, ng_presence, ng_device_signals, ng_devices
                 RESTART IDENTITY CASCADE",
            )
            .await
            .expect("truncating the test database");
    }

    Some(TestDb { db, _guard: guard })
}

/// Asserts a table is empty, with a message naming it.
pub async fn assert_empty(db: &TestDb, table: &str) {
    assert_eq!(db.count(table).await, 0, "{table} should be empty");
}
