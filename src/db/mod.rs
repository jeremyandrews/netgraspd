//! Postgres persistence.
//!
//! Schema lives in `migrations/`, embedded at build time by refinery and applied
//! on startup. There is no ORM: the queries are hand-written and the row structs
//! are plain data.
//!
//! **What is never stored:** individual packet observations. `ng_presence` holds
//! one row per online session and `ng_events` one row per state change, which is
//! the entire point of the rewrite. The predecessor wrote one row per ARP packet
//! and its database became unusable within weeks.
//!
//! Connections are plain TCP with no TLS. The daemon and its database live on
//! the same host or the same trusted LAN segment by design; if that ever stops
//! being true, the connection URL is where TLS gets configured, not here.

pub mod queries;
pub mod schema;

use anyhow::{Context, Result};
use deadpool_postgres::{Config as PoolConfig, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

use crate::config::DatabaseConfig;

/// Embedded migrations, compiled from `migrations/`.
mod embedded {
    refinery::embed_migrations!("migrations");
}

/// The highest migration version this build ships.
///
/// The read-only commands compare it against what a database records as applied,
/// so that "migrated by an older daemon" is a sentence rather than a missing
/// relation.
#[must_use]
pub fn embedded_max_version() -> i32 {
    embedded::migrations::runner()
        .get_migrations()
        .iter()
        .map(refinery::Migration::version)
        .max()
        .unwrap_or(0)
}

/// A connection pool plus the operations the daemon performs against it.
#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

impl Db {
    /// Builds a pool. Does not connect eagerly; the first query does.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection URL cannot be parsed or the pool
    /// cannot be constructed.
    pub fn connect(cfg: &DatabaseConfig) -> Result<Self> {
        let pg: tokio_postgres::Config = cfg.url.parse().with_context(|| {
            format!(
                "database.url {:?} is not a valid connection string",
                cfg.url
            )
        })?;

        let mut pool_cfg = PoolConfig::new();
        pool_cfg.manager = Some(ManagerConfig {
            // Verified recycling costs one round trip per checkout and catches a
            // connection the server closed under us, which a long-lived daemon
            // meets every time Postgres restarts.
            recycling_method: RecyclingMethod::Verified,
        });
        pool_cfg.dbname = pg.get_dbname().map(str::to_string);
        pool_cfg.user = pg.get_user().map(str::to_string);
        pool_cfg.password = pg
            .get_password()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        pool_cfg.host = pg.get_hosts().first().map(|h| match h {
            tokio_postgres::config::Host::Tcp(s) => s.clone(),
            #[cfg(unix)]
            tokio_postgres::config::Host::Unix(p) => p.to_string_lossy().into_owned(),
        });
        pool_cfg.port = pg.get_ports().first().copied();
        pool_cfg.pool = Some(deadpool_postgres::PoolConfig::new(cfg.pool_size));

        let pool = pool_cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .context("could not create the Postgres connection pool")?;
        Ok(Db { pool })
    }

    /// Applies any outstanding migrations.
    ///
    /// Runs on a dedicated connection rather than a pooled one, because refinery
    /// takes the client by exclusive reference and holds it for the duration.
    ///
    /// Before running anything it checks that the daemon, and not the Trovato
    /// plugin, created whatever `ng_` tables are already there. See
    /// [`schema::check_daemon_migrated_first`] for why that check is worth a
    /// round trip on every start.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unreachable, when the tables were
    /// created by the plugin rather than by the daemon, or when a migration
    /// fails.
    pub async fn migrate(url: &str) -> Result<()> {
        let (mut client, connection) = tokio_postgres::connect(url, NoTls)
            .await
            .context("could not connect to Postgres to run migrations")?;
        let handle = tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(%err, "migration connection closed");
            }
        });

        schema::check_daemon_migrated_first(&client).await?;

        let report = embedded::migrations::runner()
            .run_async(&mut client)
            .await
            .context("migration failed")?;
        for migration in report.applied_migrations() {
            tracing::info!(
                version = migration.version(),
                name = migration.name(),
                "migration applied"
            );
        }
        drop(client);
        handle.abort();
        Ok(())
    }

    /// Checks out a pooled connection.
    ///
    /// # Errors
    ///
    /// Returns an error when no connection can be obtained.
    pub async fn client(&self) -> Result<deadpool_postgres::Client> {
        self.pool
            .get()
            .await
            .context("could not obtain a Postgres connection")
    }

    /// Confirms the database is reachable and the schema is present.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection fails or `ng_devices` is missing.
    pub async fn health_check(&self) -> Result<()> {
        let client = self.client().await?;
        client
            .query_one("SELECT COUNT(*) FROM ng_devices", &[])
            .await
            .context("ng_devices is not readable; has the schema been migrated?")?;
        Ok(())
    }

    /// Verifies every `ng_` table matches what this build expects.
    ///
    /// # Errors
    ///
    /// Returns an error naming the table and column on any divergence.
    pub async fn preflight(&self) -> Result<()> {
        let client = self.client().await?;
        schema::preflight(&client).await
    }

    /// Refuses to read from a database this build cannot read honestly.
    ///
    /// What [`migrate`](Self::migrate) and [`preflight`](Self::preflight) do for
    /// the daemon, in one call, for the commands that only read. They never
    /// migrate, so nothing else has checked anything for them.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unreachable, has no netgrasp
    /// schema, has one the plugin built, is migrated short of this build, or
    /// diverges from the expected columns.
    pub async fn require_schema(&self) -> Result<()> {
        let client = self.client().await?;
        schema::check_readable(&client, embedded_max_version()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_url_fails_at_construction_not_at_first_query() {
        let cfg = DatabaseConfig {
            url: "this is not a connection string".into(),
            pool_size: 2,
        };
        let err = match Db::connect(&cfg) {
            Ok(_) => panic!("a malformed URL must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("not a valid connection string"),
            "{err}"
        );
    }

    #[test]
    fn a_well_formed_url_builds_a_pool_without_connecting() {
        let cfg = DatabaseConfig {
            url: "postgres://someone:secret@db.invalid:5432/netgrasp".into(),
            pool_size: 3,
        };
        Db::connect(&cfg).expect("pool construction must not require a reachable server");
    }

    #[test]
    fn the_migration_set_is_embedded_and_ordered() {
        let runner = embedded::migrations::runner();
        let migrations = runner.get_migrations();
        assert!(!migrations.is_empty(), "migrations/ produced nothing");
        // refinery sorts by version when it runs, not when it lists, so the
        // invariant worth asserting is that the versions are unique and
        // contiguous from one. A duplicate version silently drops a migration.
        let mut versions: Vec<i32> = migrations
            .iter()
            .map(refinery::Migration::version)
            .collect();
        versions.sort_unstable();
        let expected: Vec<i32> =
            (1..=i32::try_from(versions.len()).expect("few migrations")).collect();
        assert_eq!(
            versions, expected,
            "migration versions must be 1..n with no gaps or repeats"
        );
        println!("embedded migrations: {versions:?}");
    }
}
