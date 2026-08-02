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

use anyhow::{Context, Result};
use deadpool_postgres::{Config as PoolConfig, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

use crate::config::DatabaseConfig;

/// Embedded migrations, compiled from `migrations/`.
mod embedded {
    refinery::embed_migrations!("migrations");
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
    /// # Errors
    ///
    /// Returns an error when the database is unreachable or a migration fails.
    pub async fn migrate(url: &str) -> Result<()> {
        let (mut client, connection) = tokio_postgres::connect(url, NoTls)
            .await
            .context("could not connect to Postgres to run migrations")?;
        let handle = tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(%err, "migration connection closed");
            }
        });

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
        let mut last = 0;
        for m in migrations {
            assert!(m.version() > last, "migration versions must increase");
            last = m.version();
        }
    }
}
