//! The `docchain-migrate` composition root: it connects only as the migration owner, refuses a
//! superuser session, and applies the embedded migrations, including the runtime role's grants.

use sqlx::postgres::PgPoolOptions;
use thiserror::Error;

use crate::{
    config::MigrationSettings,
    harness::migration_connect_options,
    store::{migrate_schema, schema_exists, session_is_superuser},
};

/// The step at which migration stopped. It names no user, password, path, or SQL error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct MigrateError(&'static str);

/// Connects as the owner and brings the configured schema up to date.
///
/// In order: it connects, refuses the session when its session or current role is a
/// superuser, checks that the schema exists, and applies every pending migration. It never
/// creates the schema.
///
/// # Errors
///
/// [`MigrateError`] naming the failed step: `database connection` when it cannot connect or
/// its schema query fails, `database owner role`, `database schema` when the schema is absent,
/// or `database migration`.
pub async fn run(settings: &MigrationSettings) -> Result<(), MigrateError> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(migration_connect_options(settings))
        .await
        .map_err(|_| MigrateError("database connection"))?;
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| MigrateError("database connection"))?;
    // Before any other statement: a superuser's rights reach the whole cluster.
    if session_is_superuser(&mut conn).await {
        return Err(MigrateError("database owner role"));
    }
    match schema_exists(&mut conn, settings.schema.as_str()).await {
        Ok(true) => {}
        Ok(false) => return Err(MigrateError("database schema")),
        // A failed query observes nothing about the schema.
        Err(_) => return Err(MigrateError("database connection")),
    }
    let migrated = migrate_schema(&mut conn)
        .await
        .map_err(|_| MigrateError("database migration"));
    drop(conn);
    pool.close().await;
    migrated
}
