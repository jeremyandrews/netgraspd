//! Shared harness for the integration tests.
//!
//! The tests need a real Postgres because the point of them is that the schema,
//! the upserts and the partial unique indexes behave as designed. Set
//! `NETGRASPD_TEST_DATABASE_URL` to point somewhere else; the default is a local
//! `netgrasp` database.
//!
//! The variable is deliberately spelled `NETGRASPD_`, not `NETGRASP_`. The
//! daemon reads every `NETGRASP_`-prefixed environment variable as configuration
//! and rejects unknown keys, so a harness variable under that prefix makes every
//! configuration test in the same run fail with "failed to assemble
//! configuration". It did, once.
//!
//! When no database is reachable the harness returns `None` and the test prints
//! why and passes. A developer without Postgres running should still get a green
//! `cargo test` on everything else, and CI sets the variable so the coverage is
//! not quietly lost there.

// Each integration test binary compiles this module separately, so a helper
// only one of them uses reads as dead code in the others.
#![allow(dead_code)]

use std::sync::{Arc, Mutex as StdMutex};

use netgraspd::db::Db;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
    let url = test_url();

    let cfg = netgraspd::config::DatabaseConfig {
        url: url.clone(),
        pool_size: 4,
    };
    let db = Db::connect(&cfg).expect("a valid test connection URL");
    if db.client().await.is_err() {
        eprintln!("skipping: no Postgres at {url}");
        return None;
    }
    // A migration failure against a database that *is* reachable is a real
    // failure and must never be mistaken for "no Postgres here". Treating it as
    // a skip is how a whole test binary turns into thirteen green ticks that
    // proved nothing, which is exactly what happened once.
    Db::migrate(&url).await.unwrap_or_else(|err| {
        panic!("the test database at {url} is reachable but could not be migrated: {err:#}")
    });

    {
        let client = db.client().await.expect("a pooled connection");
        client
            .batch_execute(
                "TRUNCATE ng_events, ng_ip_history, ng_presence, ng_location_history,
                          ng_people, ng_device_signals, ng_devices,
                          ng_notify_status, ng_notify_requests,
                          ng_daemon_status, ng_enrichment_status
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

/// The connection URL the harness is using.
pub fn test_url() -> String {
    std::env::var("NETGRASPD_TEST_DATABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string())
}

/// The same database, connected to as somebody else.
///
/// For the one test that has to prove a catalog lookup is indifferent to the
/// connecting role, which is the whole shape of the bug: the plugin creates the
/// `ng_` tables as one role and the daemon connects as another.
pub fn test_url_as_role(user: &str, password: &str) -> String {
    let url = test_url();
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        // Not a URL. The caller will fail to connect and skip, saying so.
        return url;
    };
    let rest = &url[scheme_end..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host_start = rest[..authority_end].rfind('@').map_or(0, |at| at + 1);
    format!(
        "{}{user}:{password}@{}",
        &url[..scheme_end],
        &rest[host_start..]
    )
}

/// Drops every table and migrates from nothing.
///
/// Two tests deliberately wreck the schema, because the failures worth proving
/// are exactly the ones a wrecked schema causes. Both call this afterwards: a
/// test that leaves `refinery_schema_history` missing makes every test after it
/// in the same binary *skip*, and a skipped test is a green tick that proved
/// nothing.
pub async fn rebuild_schema(db: &TestDb) {
    // Every table the contract names, from the contract, so a table added in a
    // later migration cannot survive the drop and then fail its own CREATE.
    let tables: Vec<&str> = netgraspd::db::schema::EXPECTED
        .iter()
        .map(|(table, _)| *table)
        .collect();
    db.execute(&format!(
        "DROP TABLE IF EXISTS {}, refinery_schema_history CASCADE",
        tables.join(", ")
    ))
    .await;
    Db::migrate(&test_url())
        .await
        .expect("rebuilding the test schema");
}

/// A scratch database beside the test one, migrated to `version` by this
/// build's own migrations, as an earlier release would have left it.
///
/// For proving an upgrade without disturbing the shared test database. The
/// caller holds [`test_db`]'s lock, so two of these never race, and drops it
/// with [`drop_scratch_database`]. `None` when no Postgres is reachable.
pub async fn scratch_database(name: &str, version: u32) -> Option<String> {
    let admin = test_url();
    let (client, connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
        .await
        .ok()?;
    tokio::spawn(connection);
    // Two statements, not one batch: a multi-statement batch is one implicit
    // transaction, and DROP DATABASE refuses to run inside one.
    client
        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .await
        .expect("dropping a leftover scratch database");
    client
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .expect("creating a scratch database");
    let (base, _) = admin.rsplit_once('/').expect("a URL with a database name");
    let url = format!("{base}/{name}");
    Db::migrate_to(&url, version)
        .await
        .expect("migrating the scratch database");
    Some(url)
}

/// Drops a database [`scratch_database`] made.
pub async fn drop_scratch_database(name: &str) {
    let (admin, connection) = tokio_postgres::connect(&test_url(), tokio_postgres::NoTls)
        .await
        .expect("the admin connection");
    tokio::spawn(connection);
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .await
        .expect("dropping the scratch database");
}

impl TestDb {
    /// Inserts a device directly, returning its id.
    ///
    /// For tests about the tables downstream of `ng_devices`, which need a
    /// device to hang off and do not care how it was discovered.
    pub async fn seed_device(&self, mac: &str, state: &str) -> i64 {
        let client = self.client().await;
        let row = client
            .query_one(
                "INSERT INTO ng_devices (mac, state, first_seen_at, last_seen_at)
                 VALUES ($1, $2, now(), now())
                 RETURNING id",
                &[&mac, &state],
            )
            .await
            .unwrap_or_else(|err| panic!("seeding device {mac}: {err}"));
        row.get(0)
    }

    /// Runs a statement, panicking with the statement text on failure.
    pub async fn execute(&self, sql: &str) {
        let client = self.client().await;
        client
            .batch_execute(sql)
            .await
            .unwrap_or_else(|err| panic!("running {sql:?}: {err}"));
    }

    /// Runs a scalar query returning one nullable `i64`.
    pub async fn maybe_scalar(&self, sql: &str) -> Option<i64> {
        let client = self.client().await;
        let row = client
            .query_one(sql, &[])
            .await
            .unwrap_or_else(|err| panic!("running {sql:?}: {err}"));
        row.get(0)
    }
}

/// One request the fake ntfy received.
#[derive(Debug, Clone)]
pub struct Logged {
    /// Request path, which is the topic.
    pub path: String,
    /// The `X-Title` header.
    pub title: String,
    /// The `Authorization` header, when sent.
    pub authorization: Option<String>,
    /// The message body.
    pub body: String,
}

/// A minimal HTTP server that records every request and answers with
/// `status`. Enough of HTTP/1.1 for reqwest, and nothing more. It never
/// forwards anything: it stands in for ntfy so that no test reaches the real one.
pub async fn fake_ntfy(status: u16) -> (String, Arc<StdMutex<Vec<Logged>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let log: Arc<StdMutex<Vec<Logged>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];
                let (head_len, content_length) = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buffer[..end]).to_string();
                        let length = head
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        break (end + 4, length);
                    }
                };
                while buffer.len() < head_len + content_length {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buffer[..head_len]).to_string();
                let header = |name: &str| {
                    head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                    })
                };
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                sink.lock().expect("log").push(Logged {
                    path,
                    title: header("x-title").unwrap_or_default(),
                    authorization: header("authorization"),
                    body: String::from_utf8_lossy(&buffer[head_len..]).to_string(),
                });
                let reason = if status == 200 { "OK" } else { "Error" };
                let reply = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}"), log)
}
