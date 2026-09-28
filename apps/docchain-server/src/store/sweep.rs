//! The startup sweep's filesystem inventory and PostgreSQL reference read, and every bound the
//! lease and the sweep use.
//!
//! Directory entries are classified by name and by the type the entry itself reports, which
//! never follows a symlink. Only regular files with an object or temporary name are candidates;
//! nothing else is opened, followed, or removed.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use docchain_application::{
    DebrisEntry, DebrisInventory, Inventory, ReferenceScan, RemovedCounts, StoreError,
};
use docchain_domain::ObjectId;
use sqlx::{Connection as _, PgConnection};

use super::{FileDocumentStore, PgExchangeStore, map_io, map_sql};

/// Most entries one sweep lists; a larger root skips the sweep.
pub(crate) const SWEEP_MAX_ENTRIES: usize = 100_000;
/// How long a start waits for shared locks when exclusive ones are refused.
const LEASE_WAIT: Duration = Duration::from_secs(10);
/// Interval between lock attempts and between writer-drain queries.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long the writer drain waits for recorded transactions to end.
const DRAIN_WAIT: Duration = Duration::from_secs(10);
/// Longest single writer-drain query.
const DRAIN_QUERY: Duration = Duration::from_secs(2);
/// Longest listing of the store root.
const INVENTORY_DEADLINE: Duration = Duration::from_secs(10);
/// `statement_timeout` inside the reference read.
const SCAN_STATEMENT_TIMEOUT: Duration = Duration::from_secs(10);
/// `lock_timeout` inside the reference read.
const SCAN_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// Outer bound on the whole reference read.
const SCAN_DEADLINE: Duration = Duration::from_secs(15);
/// Longest removal pass.
const REMOVAL_DEADLINE: Duration = Duration::from_secs(20);
/// Rows fetched from the reference cursor at a time.
const SCAN_BATCH: i64 = 1_000;

/// Every bound of the lease, the writer drain, and the sweep. Production uses
/// [`SweepBounds::DEFAULT`]; only the test-support harness shortens them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SweepBounds {
    /// Most entries one listing accepts.
    pub max_entries: usize,
    /// How long acquisition waits for shared holds.
    pub lease_wait: Duration,
    /// Interval between lock attempts and drain queries.
    pub poll: Duration,
    /// How long the writer drain waits.
    pub drain: Duration,
    /// Longest single drain query.
    pub drain_query: Duration,
    /// Longest listing.
    pub inventory: Duration,
    /// `statement_timeout` of the reference read.
    pub scan_statement: Duration,
    /// `lock_timeout` of the reference read.
    pub scan_lock: Duration,
    /// Outer bound on the reference read.
    pub scan: Duration,
    /// Longest removal pass.
    pub removal: Duration,
}

impl SweepBounds {
    /// The bounds every production start uses.
    pub const DEFAULT: Self = Self {
        max_entries: SWEEP_MAX_ENTRIES,
        lease_wait: LEASE_WAIT,
        poll: POLL_INTERVAL,
        drain: DRAIN_WAIT,
        drain_query: DRAIN_QUERY,
        inventory: INVENTORY_DEADLINE,
        scan_statement: SCAN_STATEMENT_TIMEOUT,
        scan_lock: SCAN_LOCK_TIMEOUT,
        scan: SCAN_DEADLINE,
        removal: REMOVAL_DEADLINE,
    };
}

impl Default for SweepBounds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The adapter's own names in the store root. They are never candidates and are not counted.
pub(crate) const LOCK_NAME: &str = ".docchain-lock";
pub(crate) const BINDING_NAME: &str = ".docchain-binding";
pub(crate) const BINDING_TEMPORARY_NAME: &str = ".docchain-binding.tmp";

/// What a directory-entry name is, before its type is considered.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EntryName {
    /// A name the domain parses as an object ID.
    Object(ObjectId),
    /// `.<object-id>.tmp`, left by an interrupted write.
    Temporary(ObjectId),
    /// One of the adapter's control files.
    Control,
    /// Anything else, including a name that is not UTF-8.
    Other,
}

/// Classifies one directory-entry name.
pub(crate) fn classify(name: &OsStr) -> EntryName {
    let Some(name) = name.to_str() else {
        return EntryName::Other;
    };
    if matches!(name, LOCK_NAME | BINDING_NAME | BINDING_TEMPORARY_NAME) {
        return EntryName::Control;
    }
    if let Ok(object) = ObjectId::new(name) {
        return EntryName::Object(object);
    }
    name.strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .and_then(|inner| ObjectId::new(inner).ok())
        .map_or(EntryName::Other, EntryName::Temporary)
}

/// The device and inode of the store root when it was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootIdentity {
    device: u64,
    inode: u64,
}

impl RootIdentity {
    /// Reads the root's identity without following a symlink; the root must be a directory.
    pub(crate) fn of(root: &Path) -> Result<Self, StoreError> {
        let metadata = std::fs::symlink_metadata(root).map_err(map_io)?;
        if !metadata.file_type().is_dir() {
            return Err(StoreError::Permanent);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Fails unless `root` is still the directory that was opened.
    pub(crate) fn check(self, root: &Path) -> Result<(), StoreError> {
        if Self::of(root)? == self {
            Ok(())
        } else {
            Err(StoreError::Permanent)
        }
    }
}

/// Whether an unbound root may be bound: `Some(false)` when no entry of any type has an object
/// or temporary name, `Some(true)` when one does, and `None` when the root is over the bound.
pub(crate) fn holds_candidate_names(
    root: &Path,
    identity: RootIdentity,
    bounds: &SweepBounds,
) -> Result<Option<bool>, StoreError> {
    let deadline = Instant::now() + bounds.inventory;
    identity.check(root)?;
    let mut entries = 0_usize;
    for entry in std::fs::read_dir(root).map_err(map_io)? {
        if Instant::now() > deadline {
            return Err(StoreError::Transient);
        }
        let entry = entry.map_err(map_io)?;
        entries = entries.saturating_add(1);
        if entries > bounds.max_entries {
            return Ok(None);
        }
        if matches!(
            classify(&entry.file_name()),
            EntryName::Object(_) | EntryName::Temporary(_)
        ) {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

/// One bounded listing, on a blocking thread.
fn list(
    root: &Path,
    identity: RootIdentity,
    bounds: &SweepBounds,
) -> Result<Inventory, StoreError> {
    let deadline = Instant::now() + bounds.inventory;
    identity.check(root)?;
    let mut objects = BTreeSet::new();
    let mut temporaries = BTreeSet::new();
    let mut skipped = 0_u64;
    let mut entries = 0_usize;
    for entry in std::fs::read_dir(root).map_err(map_io)? {
        if Instant::now() > deadline {
            return Err(StoreError::Transient);
        }
        let entry = entry.map_err(map_io)?;
        entries = entries.saturating_add(1);
        if entries > bounds.max_entries {
            return Ok(Inventory::OverBound);
        }
        let class = classify(&entry.file_name());
        let candidates = match class {
            EntryName::Control => continue,
            EntryName::Other => {
                skipped = skipped.saturating_add(1);
                continue;
            }
            EntryName::Object(_) => &mut objects,
            EntryName::Temporary(_) => &mut temporaries,
        };
        // The entry's own type: a symlink is reported as a symlink, never as its target.
        if entry.file_type().map_err(map_io)?.is_file() {
            if let EntryName::Object(id) | EntryName::Temporary(id) = class {
                candidates.insert(id);
            }
        } else {
            skipped = skipped.saturating_add(1);
        }
    }
    Ok(Inventory::Listed {
        objects,
        temporaries,
        skipped,
    })
}

/// One bounded removal pass, on a blocking thread.
fn remove(
    root: &Path,
    identity: RootIdentity,
    bounds: &SweepBounds,
    debris: &[DebrisEntry],
) -> Result<RemovedCounts, StoreError> {
    let deadline = Instant::now() + bounds.removal;
    identity.check(root)?;
    let mut counts = RemovedCounts::default();
    for entry in debris {
        if Instant::now() > deadline {
            return Err(StoreError::Transient);
        }
        let (path, removed): (PathBuf, &mut u64) = match entry {
            DebrisEntry::Object(id) => (root.join(id.as_str()), &mut counts.objects),
            DebrisEntry::Temporary(id) => (
                root.join(format!(".{}.tmp", id.as_str())),
                &mut counts.temporaries,
            ),
        };
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                counts.skipped = counts.skipped.saturating_add(1);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(map_io(error)),
        }
        match std::fs::remove_file(&path) {
            Ok(()) => *removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }
    }
    Ok(counts)
}

impl DebrisInventory for FileDocumentStore {
    /// Lists the root on a blocking thread, which checks its deadline between entries; the
    /// future awaits it, so no listing outlives the caller's lease.
    async fn inventory(&self) -> Result<Inventory, StoreError> {
        let root = self.root.clone();
        let identity = self.identity;
        let bounds = self.bounds;
        tokio::task::spawn_blocking(move || list(&root, identity, &bounds))
            .await
            .map_err(|_| StoreError::Permanent)?
    }

    /// Removes each entry that `symlink_metadata` still shows as a regular file, on a blocking
    /// thread that checks its deadline between entries.
    async fn remove_debris(&self, debris: &[DebrisEntry]) -> Result<RemovedCounts, StoreError> {
        let root = self.root.clone();
        let identity = self.identity;
        let bounds = self.bounds;
        let debris = debris.to_vec();
        tokio::task::spawn_blocking(move || remove(&root, identity, &bounds, &debris))
            .await
            .map_err(|_| StoreError::Permanent)?
    }
}

/// An injected failure of the reference read, for test-support builds only.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanFault {
    /// PostgreSQL cannot be reached.
    Unreachable,
    /// A statement in the read fails.
    QueryError,
    /// A statement in the read outlasts its timeout.
    Timeout,
    /// The stream ends one value short of the count.
    PartialStream,
}

impl ReferenceScan for PgExchangeStore {
    /// One `REPEATABLE READ READ ONLY` transaction on a connection taken out of the pool:
    /// coverage of every `object_id` column, the counts, then every value through a cursor.
    ///
    /// # Cancellation
    ///
    /// Dropping the future, or the outer deadline, drops the connection, which ends the
    /// transaction; the pool never sees it again.
    async fn referenced_among(
        &self,
        candidates: &BTreeSet<ObjectId>,
    ) -> Result<BTreeSet<ObjectId>, StoreError> {
        tokio::time::timeout(self.bounds.scan, self.scan_references(candidates))
            .await
            .map_err(|_| StoreError::Transient)?
    }
}

impl PgExchangeStore {
    async fn scan_references(
        &self,
        candidates: &BTreeSet<ObjectId>,
    ) -> Result<BTreeSet<ObjectId>, StoreError> {
        #[cfg(feature = "test-support")]
        if self.scan_fault == Some(ScanFault::Unreachable) {
            return Err(StoreError::Transient);
        }
        let mut conn = self.pool.acquire().await.map_err(map_sql)?.detach();
        let read = self.read_references(&mut conn, candidates).await;
        let _ = conn.close().await;
        read
    }

    async fn read_references(
        &self,
        conn: &mut PgConnection,
        candidates: &BTreeSet<ObjectId>,
    ) -> Result<BTreeSet<ObjectId>, StoreError> {
        let schema = quoted(&self.schema);
        sqlx::raw_sql("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await
            .map_err(map_sql)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "SET LOCAL statement_timeout = '{}ms'; SET LOCAL lock_timeout = '{}ms'",
            self.bounds.scan_statement.as_millis(),
            self.bounds.scan_lock.as_millis()
        )))
        .execute(&mut *conn)
        .await
        .map_err(map_sql)?;
        #[cfg(feature = "test-support")]
        match self.scan_fault {
            Some(ScanFault::QueryError) => {
                sqlx::raw_sql("SELECT 1 / 0")
                    .execute(&mut *conn)
                    .await
                    .map_err(map_sql)?;
            }
            Some(ScanFault::Timeout) => {
                let seconds = self.bounds.scan.as_secs_f64() + 1.0;
                sqlx::query("SELECT pg_catalog.pg_sleep($1)")
                    .bind(seconds)
                    .execute(&mut *conn)
                    .await
                    .map_err(map_sql)?;
            }
            _ => {}
        }
        let covered: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_catalog.pg_attribute a \
             JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f') \
             AND a.attname = 'object_id' AND a.attnum > 0 AND NOT a.attisdropped \
             ORDER BY 1",
        )
        .bind(&self.schema)
        .fetch_all(&mut *conn)
        .await
        .map_err(map_sql)?;
        if covered != ["audit_events", "exchanges"] {
            return Err(StoreError::Invariant);
        }
        let counted: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT (SELECT count(object_id) FROM {schema}.exchanges) \
             + (SELECT count(object_id) FROM {schema}.audit_events)"
        )))
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sql)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DECLARE docchain_references NO SCROLL CURSOR FOR \
             SELECT object_id FROM {schema}.exchanges WHERE object_id IS NOT NULL \
             UNION ALL SELECT object_id FROM {schema}.audit_events WHERE object_id IS NOT NULL"
        )))
        .execute(&mut *conn)
        .await
        .map_err(map_sql)?;
        let mut referenced = BTreeSet::new();
        let mut streamed = 0_i64;
        #[cfg(feature = "test-support")]
        let mut dropped = self.scan_fault != Some(ScanFault::PartialStream);
        loop {
            let batch: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "FETCH FORWARD {SCAN_BATCH} FROM docchain_references"
            )))
            .fetch_all(&mut *conn)
            .await
            .map_err(map_sql)?;
            if batch.is_empty() {
                break;
            }
            for value in batch {
                #[cfg(feature = "test-support")]
                if !dropped {
                    dropped = true;
                    continue;
                }
                let object = ObjectId::new(value).map_err(|_| StoreError::Invariant)?;
                streamed = streamed.checked_add(1).ok_or(StoreError::Invariant)?;
                if candidates.contains(&object) {
                    referenced.insert(object);
                }
            }
        }
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *conn)
            .await
            .map_err(map_sql)?;
        if streamed == counted {
            Ok(referenced)
        } else {
            Err(StoreError::Invariant)
        }
    }
}

/// A validated schema name as a quoted identifier.
fn quoted(schema: &str) -> String {
    format!("\"{}\"", schema.replace('"', "\"\""))
}

#[cfg(test)]
mod tests;
