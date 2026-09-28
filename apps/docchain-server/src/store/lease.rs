//! The lease every server holds on its schema and store root, the root's binding to one
//! schema, and the writer drain that decides whether a start may delete.
//!
//! The schema lock is a session advisory lock on a dedicated connection outside the pool; the
//! root lock is a `flock` on `.docchain-lock`. Both are held from composition until the
//! process ends, exclusive only while the sweep runs. A process never waits while it holds an
//! exclusive lock, so acquisition cannot deadlock.

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    time::Instant,
};

use docchain_application::SweepPermit;
use docchain_application::SweepSkip;
use sqlx::{ConnectOptions as _, Connection as _, PgConnection, postgres::PgConnectOptions};

use super::{
    FileDocumentStore,
    sweep::{BINDING_NAME, BINDING_TEMPORARY_NAME, LOCK_NAME, SweepBounds, holds_candidate_names},
};

/// The high 32 bits of the schema lock key; the low 32 bits are the schema's OID.
const LOCK_TAG: i64 = 0x4443_5357;
/// The only binding format version.
const BINDING_VERSION: &str = "docchain-store-binding 1";
/// Largest binding accepted, in bytes.
const BINDING_MAX_BYTES: u64 = 256;
/// Mode of every control file the adapter creates.
const CONTROL_MODE: u32 = 0o600;

/// The step at which the lease failed. Neither names a path, OID, or binding value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseError {
    /// The locks, the lease connection, or the writer drain failed.
    Exclusivity,
    /// The binding is unreadable, malformed, refused, or names another schema.
    Binding,
}

/// Test observation points in the lease; empty outside test-support builds.
#[derive(Clone, Debug, Default)]
pub(crate) struct LeaseHooks {
    /// Reached once the writer drain has recorded at least one transaction.
    #[cfg(feature = "test-support")]
    pub(crate) drain_recorded: Option<super::PauseGate>,
}

/// Which schema a store root belongs to: values PostgreSQL reports, never secrets, and never
/// written to diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BindingIdentity {
    cluster: u64,
    database: u32,
    schema: u32,
}

impl BindingIdentity {
    fn render(self) -> String {
        format!(
            "{BINDING_VERSION}\ncluster {}\ndatabase {}\nschema {}\n",
            self.cluster, self.database, self.schema
        )
    }

    /// Parses exactly four LF-terminated ASCII lines, with decimal numbers that have no
    /// leading zeros, in format version 1.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        if !text.is_ascii() {
            return None;
        }
        let body = text.strip_suffix('\n')?;
        let mut lines = body.split('\n');
        if lines.next()? != BINDING_VERSION {
            return None;
        }
        let cluster = field(lines.next()?, "cluster")?;
        let database = u32::try_from(field(lines.next()?, "database")?).ok()?;
        let schema = u32::try_from(field(lines.next()?, "schema")?).ok()?;
        if lines.next().is_some() {
            return None;
        }
        Some(Self {
            cluster,
            database,
            schema,
        })
    }
}

/// One `<name> <decimal>` line.
fn field(line: &str, name: &str) -> Option<u64> {
    let digits = line.strip_prefix(name)?.strip_prefix(' ')?;
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse().ok()
}

/// A held lease. Dropping it releases both locks: the connection's session ends and the
/// lock file's descriptor closes.
#[derive(Debug)]
pub(crate) struct StoreLease {
    connection: Option<PgConnection>,
    root_lock: File,
    key: i64,
    exclusive: bool,
}

impl StoreLease {
    /// Takes both locks, reads or creates the binding, and, only when both locks are exclusive
    /// and the root is bound to this schema, drains earlier writers. The permit says whether the
    /// sweep may delete.
    ///
    /// # Errors
    ///
    /// [`LeaseError::Exclusivity`] when the connection, a lock, a control file, or a drain query
    /// fails, or shared holds are not obtained within the bound; [`LeaseError::Binding`] when the
    /// binding is refused or names another schema.
    pub(crate) async fn acquire(
        options: &PgConnectOptions,
        schema: &str,
        store: &FileDocumentStore,
        bounds: &SweepBounds,
        hooks: &LeaseHooks,
    ) -> Result<(Self, SweepPermit), LeaseError> {
        let mut connection = tokio::time::timeout(bounds.lease_wait, options.connect())
            .await
            .map_err(|_| LeaseError::Exclusivity)?
            .map_err(|_| LeaseError::Exclusivity)?;
        let (identity, key) = bounded(bounds, identity(&mut connection, schema)).await?;
        let root = store.root().to_path_buf();
        let root_lock = blocking({
            let root = root.clone();
            move || open_lock_file(&root)
        })
        .await
        .map_err(|()| LeaseError::Exclusivity)?;
        let mut lease = Self {
            connection: Some(connection),
            root_lock,
            key,
            exclusive: false,
        };
        lease.lock(bounds).await?;

        let bound = blocking({
            let root = root.clone();
            move || read_binding(&root)
        })
        .await
        .map_err(|()| LeaseError::Binding)?;
        match bound {
            Some(found) if found != identity => return Err(LeaseError::Binding),
            _ if !lease.exclusive => {
                return Ok((
                    lease,
                    SweepPermit::Denied(SweepSkip::ExclusivityNotObtained),
                ));
            }
            Some(_) => {}
            None => {
                let store_identity = store.identity();
                let names = blocking({
                    let root = root.clone();
                    let bounds = *bounds;
                    move || {
                        holds_candidate_names(&root, store_identity, &bounds).map_err(|_| refused())
                    }
                })
                .await
                .map_err(|()| LeaseError::Binding)?;
                match names {
                    Some(true) => {
                        return Ok((lease, SweepPermit::Denied(SweepSkip::StoreRootNotBound)));
                    }
                    None => {
                        return Ok((lease, SweepPermit::Denied(SweepSkip::InventoryOverBound)));
                    }
                    Some(false) => {}
                }
                let created = blocking(move || {
                    create_binding(&root, identity)?;
                    read_binding(&root)
                })
                .await
                .map_err(|()| LeaseError::Binding)?;
                if created != Some(identity) {
                    return Err(LeaseError::Binding);
                }
            }
        }
        let drained = lease.drain(identity, bounds, hooks).await?;
        let permit = if drained {
            SweepPermit::Exclusive
        } else {
            SweepPermit::Denied(SweepSkip::EarlierTransactionsOpen)
        };
        Ok((lease, permit))
    }

    /// Tries both exclusive locks once; otherwise polls for shared holds on both within the
    /// bound, keeping any shared hold already taken.
    async fn lock(&mut self, bounds: &SweepBounds) -> Result<(), LeaseError> {
        let key = self.key;
        if self.advisory(bounds, Advisory::TryExclusive, key).await? {
            match self.root_lock.try_lock() {
                Ok(()) => {
                    self.exclusive = true;
                    return Ok(());
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    if !self
                        .advisory(bounds, Advisory::UnlockExclusive, key)
                        .await?
                    {
                        return Err(LeaseError::Exclusivity);
                    }
                }
                Err(std::fs::TryLockError::Error(_)) => return Err(LeaseError::Exclusivity),
            }
        }
        let deadline = Instant::now() + bounds.lease_wait;
        let (mut schema_shared, mut root_shared) = (false, false);
        loop {
            if !schema_shared {
                schema_shared = self.advisory(bounds, Advisory::TryShared, key).await?;
            }
            if !root_shared {
                root_shared = try_shared(&self.root_lock)?;
            }
            if schema_shared && root_shared {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(LeaseError::Exclusivity);
            }
            tokio::time::sleep(bounds.poll).await;
        }
    }

    /// Converts exclusive holds to shared ones: atomically for the schema lock, and by polling
    /// within the bound for the root lock. A shared lease is unchanged.
    ///
    /// # Errors
    ///
    /// [`LeaseError::Exclusivity`] when a conversion fails.
    pub(crate) async fn downgrade(&mut self, bounds: &SweepBounds) -> Result<(), LeaseError> {
        if !self.exclusive {
            return Ok(());
        }
        let key = self.key;
        if !self.advisory(bounds, Advisory::TryShared, key).await?
            || !self
                .advisory(bounds, Advisory::UnlockExclusive, key)
                .await?
        {
            return Err(LeaseError::Exclusivity);
        }
        let deadline = Instant::now() + bounds.lease_wait;
        while !try_shared(&self.root_lock)? {
            if Instant::now() >= deadline {
                return Err(LeaseError::Exclusivity);
            }
            tokio::time::sleep(bounds.poll).await;
        }
        self.exclusive = false;
        Ok(())
    }

    /// Ends the lease session, then closes the lock file, as a process exit would.
    pub(crate) async fn release(mut self) {
        if let Some(connection) = self.connection.take() {
            let _ = connection.close().await;
        }
    }

    /// Records the transactions that hold or await a lock stronger than `ROW SHARE` on the
    /// schema, and waits within the bound for all of them to end. `false` means some remain.
    async fn drain(
        &mut self,
        identity: BindingIdentity,
        bounds: &SweepBounds,
        hooks: &LeaseHooks,
    ) -> Result<bool, LeaseError> {
        let started = Instant::now();
        let recorded = self.open_writers(identity, bounds).await?;
        if recorded.is_empty() {
            return Ok(true);
        }
        #[cfg(feature = "test-support")]
        if let Some(gate) = &hooks.drain_recorded {
            gate.pass().await;
        }
        #[cfg(not(feature = "test-support"))]
        let _ = hooks;
        loop {
            if Instant::now().saturating_duration_since(started) >= bounds.drain {
                return Ok(false);
            }
            tokio::time::sleep(bounds.poll).await;
            let open = self.open_writers(identity, bounds).await?;
            if recorded.is_disjoint(&open) {
                return Ok(true);
            }
        }
    }

    async fn open_writers(
        &mut self,
        identity: BindingIdentity,
        bounds: &SweepBounds,
    ) -> Result<BTreeSet<String>, LeaseError> {
        let connection = self.connection.as_mut().ok_or(LeaseError::Exclusivity)?;
        let query = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT l.virtualtransaction FROM pg_catalog.pg_locks l \
             JOIN pg_catalog.pg_class c ON c.oid = l.relation \
             WHERE l.locktype = 'relation' AND l.database::bigint = $1 \
             AND c.relnamespace::bigint = $2 \
             AND l.mode NOT IN ('AccessShareLock', 'RowShareLock') \
             AND l.pid IS DISTINCT FROM pg_catalog.pg_backend_pid() \
             AND l.virtualtransaction IS NOT NULL",
        )
        .bind(i64::from(identity.database))
        .bind(i64::from(identity.schema))
        .fetch_all(connection);
        let rows = tokio::time::timeout(bounds.drain_query, query)
            .await
            .map_err(|_| LeaseError::Exclusivity)?
            .map_err(|_| LeaseError::Exclusivity)?;
        Ok(rows.into_iter().collect())
    }

    /// Calls one advisory-lock function on the lease session and returns its boolean result.
    async fn advisory(
        &mut self,
        bounds: &SweepBounds,
        function: Advisory,
        key: i64,
    ) -> Result<bool, LeaseError> {
        let connection = self.connection.as_mut().ok_or(LeaseError::Exclusivity)?;
        let statement = match function {
            Advisory::TryExclusive => "SELECT pg_catalog.pg_try_advisory_lock($1)",
            Advisory::TryShared => "SELECT pg_catalog.pg_try_advisory_lock_shared($1)",
            Advisory::UnlockExclusive => "SELECT pg_catalog.pg_advisory_unlock($1)",
        };
        let query = sqlx::query_scalar::<_, bool>(statement)
            .bind(key)
            .fetch_one(connection);
        tokio::time::timeout(bounds.drain_query, query)
            .await
            .map_err(|_| LeaseError::Exclusivity)?
            .map_err(|_| LeaseError::Exclusivity)
    }
}

/// The session advisory-lock functions the lease calls.
#[derive(Clone, Copy)]
enum Advisory {
    TryExclusive,
    TryShared,
    UnlockExclusive,
}

/// One non-blocking attempt at a shared `flock`.
fn try_shared(file: &File) -> Result<bool, LeaseError> {
    match file.try_lock_shared() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(_)) => Err(LeaseError::Exclusivity),
    }
}

/// Runs one lease query within the per-query bound.
async fn bounded<T>(
    bounds: &SweepBounds,
    query: impl Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, LeaseError> {
    tokio::time::timeout(bounds.drain_query, query)
        .await
        .map_err(|_| LeaseError::Exclusivity)?
        .map_err(|_| LeaseError::Exclusivity)
}

/// The cluster, database, and schema identity, and the schema lock key.
async fn identity(
    connection: &mut PgConnection,
    schema: &str,
) -> Result<(BindingIdentity, i64), sqlx::Error> {
    let (cluster, database, namespace): (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT (SELECT system_identifier FROM pg_catalog.pg_control_system()), \
         (SELECT oid::bigint FROM pg_catalog.pg_database \
          WHERE datname = pg_catalog.current_database()), \
         (SELECT oid::bigint FROM pg_catalog.pg_namespace WHERE nspname = $1)",
    )
    .bind(schema)
    .fetch_one(connection)
    .await?;
    let invalid = || sqlx::Error::Protocol("catalog identity out of range".into());
    let database = u32::try_from(database).map_err(|_| invalid())?;
    let schema = u32::try_from(namespace.ok_or_else(invalid)?).map_err(|_| invalid())?;
    let identity = BindingIdentity {
        cluster: cluster.cast_unsigned(),
        database,
        schema,
    };
    Ok((identity, (LOCK_TAG << 32) | i64::from(schema)))
}

/// Runs control-file I/O on a blocking thread and awaits it, so none outlives the caller.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, ()> {
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}

fn refused() -> std::io::Error {
    std::io::Error::other("control file refused")
}

/// Opens an existing control file read-only and without create, after `symlink_metadata`
/// shows a regular file. The handle and a second `symlink_metadata` must show the same device
/// and inode, and the mode must have no group or other bits. `None` means the name is absent.
pub(crate) fn open_control(path: &Path) -> std::io::Result<Option<File>> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !before.file_type().is_file() {
        return Err(refused());
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let opened = file.metadata()?;
    let after = std::fs::symlink_metadata(path)?;
    let same = |metadata: &std::fs::Metadata| {
        metadata.file_type().is_file()
            && metadata.dev() == before.dev()
            && metadata.ino() == before.ino()
    };
    if !same(&opened) || !same(&after) || opened.mode() & 0o077 != 0 {
        return Err(refused());
    }
    Ok(Some(file))
}

/// Creates a new control file with `create_new` and mode `0600`; an existing name of any type,
/// including a dangling symlink, is left alone.
fn create_control(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(CONTROL_MODE)
        .open(path)
}

/// Opens `.docchain-lock`, creating it first when absent. It is never written or truncated.
pub(crate) fn open_lock_file(root: &Path) -> std::io::Result<File> {
    let path = root.join(LOCK_NAME);
    for _ in 0..2 {
        if let Some(file) = open_control(&path)? {
            return Ok(file);
        }
        match create_control(&path) {
            Ok(created) => drop(created),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(refused())
}

/// Reads the binding: `None` when absent, an error when refused, too large, or malformed.
pub(crate) fn read_binding(root: &Path) -> std::io::Result<Option<BindingIdentity>> {
    let Some(file) = open_control(&root.join(BINDING_NAME))? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(BINDING_MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > BINDING_MAX_BYTES) {
        return Err(refused());
    }
    BindingIdentity::parse(&bytes).map(Some).ok_or_else(refused)
}

/// Writes the binding through a temporary file and a hard link, which fails if a binding
/// already exists, then syncs the root. A binding another process created first is kept.
pub(crate) fn create_binding(root: &Path, identity: BindingIdentity) -> std::io::Result<()> {
    let temporary: PathBuf = root.join(BINDING_TEMPORARY_NAME);
    match std::fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_file() => std::fs::remove_file(&temporary)?,
        Ok(_) => return Err(refused()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = create_control(&temporary)?;
    let written = file
        .write_all(identity.render().as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    let linked = written.and_then(|()| std::fs::hard_link(&temporary, root.join(BINDING_NAME)));
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match linked {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    File::open(root)?.sync_all()
}

#[cfg(test)]
mod tests;
