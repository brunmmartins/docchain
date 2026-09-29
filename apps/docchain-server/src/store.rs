//! PostgreSQL exchange/event adapter and filesystem ciphertext adapter.

use std::{
    borrow::Cow,
    collections::BTreeSet,
    future::Future,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, Instant},
};

use docchain_application::{
    AcceptanceOutcome, AuditCreditSnapshot, AuditEventStore, AuditReadError, AuditReadRequest,
    AuditStoredPage, CreditPosting, DocumentStore, EventIntegrity, ExchangeRecord, ExchangeStore,
    StoreError,
};
use docchain_domain::{
    AuditEvent, AuditSnapshot, Checkpoint, CreditLedgerEntry, CreditLedgerTransaction, DocumentId,
    DocumentVersion, EventDraft, EventKind, ExchangeId, ISSUANCE_ACCOUNT, IdempotencyKey, ObjectId,
    RequestNonce, Timestamp, WalletId, event_signature_input,
};
use sqlx::{
    PgConnection, PgPool, Postgres, Row as _, SqlStr, Transaction,
    error::BoxDynError,
    migrate::{Migration, MigrationSource, MigrationType, Migrator},
};
use tokio::{fs, io::AsyncWriteExt as _, sync::Mutex, task::JoinHandle};

mod lease;
mod sweep;

pub(crate) use lease::{LeaseError, LeaseHooks, StoreLease};
use sweep::RootIdentity;
#[cfg(feature = "test-support")]
pub use sweep::ScanFault;
pub use sweep::SweepBounds;

/// A test-support pause point. While armed, a task that reaches it waits until it is opened;
/// every arrival is counted, armed or not, so a test can also wait for a step to be reached.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
pub struct PauseGate(std::sync::Arc<tokio::sync::watch::Sender<GateState>>);

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Default)]
struct GateState {
    armed: bool,
    reached: usize,
}

#[cfg(feature = "test-support")]
impl Default for PauseGate {
    fn default() -> Self {
        Self(std::sync::Arc::new(tokio::sync::watch::Sender::new(
            GateState::default(),
        )))
    }
}

#[cfg(feature = "test-support")]
impl PauseGate {
    /// Makes the next arrivals wait.
    pub fn arm(&self) {
        self.0.send_modify(|state| state.armed = true);
    }

    /// Releases every waiting task and lets later arrivals pass.
    pub fn open(&self) {
        self.0.send_modify(|state| state.armed = false);
    }

    /// Waits until at least `count` arrivals in total have reached the gate.
    pub async fn reached(&self, count: usize) {
        let mut state = self.0.subscribe();
        let _ = state.wait_for(|state| state.reached >= count).await;
    }

    /// Counts one arrival, then waits while the gate is armed.
    pub(crate) async fn pass(&self) {
        let mut state = self.0.subscribe();
        self.0
            .send_modify(|state| state.reached = state.reached.saturating_add(1));
        let _ = state.wait_for(|state| !state.armed).await;
    }
}

/// The forward-only migrations, embedded so the binary does not depend on the source tree.
///
/// Every file in `migrations/` must appear here, in version order; a unit test compares this list
/// with the directory.
const MIGRATIONS: [(i64, &str, &str); 6] = [
    (
        1,
        "first exchange",
        include_str!("../migrations/0001_first_exchange.sql"),
    ),
    (
        2,
        "verified exchange",
        include_str!("../migrations/0002_verified_exchange.sql"),
    ),
    (
        3,
        "scoped acceptance and balanced credits",
        include_str!("../migrations/0003_scoped_acceptance_and_balanced_credits.sql"),
    ),
    (
        4,
        "append only and sender scoped replay",
        include_str!("../migrations/0004_append_only_and_sender_scoped_replay.sql"),
    ),
    (
        5,
        "record send commit time",
        include_str!("../migrations/0005_record_send_commit_time.sql"),
    ),
    (
        6,
        "least privilege runtime grants",
        include_str!("../migrations/0006_least_privilege_runtime_grants.sql"),
    ),
];

#[derive(Debug)]
struct EmbeddedMigrations;

impl MigrationSource<'static> for EmbeddedMigrations {
    fn resolve(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>> {
        Box::pin(async {
            Ok(MIGRATIONS
                .iter()
                .map(|(version, description, sql)| {
                    Migration::new(
                        *version,
                        Cow::Borrowed(*description),
                        MigrationType::Simple,
                        SqlStr::from_static(sql),
                        false,
                    )
                })
                .collect())
        })
    }
}

/// Applies every pending migration in order, each in its own transaction, on one connection.
///
/// Each applied version is recorded with its checksum; a changed applied migration is refused.
/// Only the migration owner runs this, on a connection that sets `docchain.runtime_role`; the
/// server never does.
///
/// # Errors
///
/// [`StoreError::Permanent`] when a migration fails or an applied one was changed. SQLx keeps
/// its database-wide migration lock on the connection of a failed run until it closes.
pub(crate) async fn migrate_schema(conn: &mut PgConnection) -> Result<(), StoreError> {
    // `run_direct` is what `Migrator::run` calls once it holds a connection. Calling it with the
    // connection itself keeps callers' futures `Send` for every lifetime, which `run` cannot:
    // SQLx implements `Acquire` for a connection reference at one specific lifetime only.
    Migrator::new(EmbeddedMigrations)
        .await
        .map_err(|_| StoreError::Permanent)?
        .run_direct(None, conn, false)
        .await
        .map_err(|_| StoreError::Permanent)
}

/// Whether `role` is a superuser. A role that `pg_roles` does not list counts as one, so a
/// missing or unreadable role never passes as safe.
///
/// # Errors
///
/// [`StoreError`] when the catalog cannot be read.
pub(crate) async fn role_is_superuser(
    conn: &mut PgConnection,
    role: &str,
) -> Result<bool, StoreError> {
    sqlx::query_scalar("SELECT COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = $1), TRUE)")
        .bind(role)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sql)
}

/// The session and current roles of a connection, which differ after `SET ROLE`.
///
/// # Errors
///
/// [`StoreError`] when the connection fails.
pub(crate) async fn session_roles(conn: &mut PgConnection) -> Result<(String, String), StoreError> {
    sqlx::query_as("SELECT session_user::text, current_user::text")
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sql)
}

/// Whether either role of this connection is a superuser, or cannot be checked.
pub(crate) async fn session_is_superuser(conn: &mut PgConnection) -> bool {
    let Ok((session, current)) = session_roles(conn).await else {
        return true;
    };
    for role in [session, current] {
        if !matches!(role_is_superuser(conn, &role).await, Ok(false)) {
            return true;
        }
    }
    false
}

/// Whether the configured schema exists. It reads `pg_namespace`, because `current_schema()` is
/// NULL for a role without USAGE on the schema.
///
/// # Errors
///
/// [`StoreError`] when the catalog cannot be read.
pub(crate) async fn schema_exists(
    conn: &mut PgConnection,
    schema: &str,
) -> Result<bool, StoreError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)")
        .bind(schema)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sql)
}

/// How the migration ledger in a schema compares with the embedded migrations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MigrationState {
    /// Every embedded version is applied, successfully and unchanged, and nothing else is.
    Current,
    /// The connected role cannot use the schema or read the ledger, or an embedded version is
    /// not recorded.
    Pending,
    /// An applied version failed, has a different checksum, or is unknown to this binary.
    Mismatch,
}

/// Compares the ledger with the embedded migrations. It reads catalogs and the ledger only; it
/// writes nothing and takes no lock.
///
/// # Errors
///
/// [`StoreError`] when a read fails for a reason other than a missing privilege.
pub(crate) async fn migration_state(
    conn: &mut PgConnection,
    schema: &str,
) -> Result<MigrationState, StoreError> {
    let readable: bool = sqlx::query_scalar(
        "SELECT COALESCE(( \
             SELECT has_schema_privilege(current_user, oid, 'USAGE') \
                 AND to_regclass(format('%I._sqlx_migrations', nspname)) IS NOT NULL \
                 AND has_table_privilege( \
                     to_regclass(format('%I._sqlx_migrations', nspname)), 'SELECT') \
             FROM pg_namespace WHERE nspname = $1), FALSE)",
    )
    .bind(schema.to_owned())
    .fetch_one(&mut *conn)
    .await
    .map_err(map_sql)?;
    if !readable {
        return Ok(MigrationState::Pending);
    }
    // The schema is a validated lower-case identifier; it is quoted as one all the same.
    let applied: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT version, success, checksum FROM \"{schema}\"._sqlx_migrations ORDER BY version"
    )))
    .fetch_all(&mut *conn)
    .await
    .map_err(map_sql)?;
    let embedded = Migrator::new(EmbeddedMigrations)
        .await
        .map_err(|_| StoreError::Invariant)?;
    if embedded.iter().any(|migration| {
        !applied
            .iter()
            .any(|(version, _, _)| *version == migration.version)
    }) {
        return Ok(MigrationState::Pending);
    }
    let unchanged = applied.iter().all(|(version, success, checksum)| {
        *success
            && embedded.iter().any(|migration| {
                migration.version == *version && migration.checksum.as_ref() == checksum.as_slice()
            })
    });
    Ok(if unchanged {
        MigrationState::Current
    } else {
        MigrationState::Mismatch
    })
}

/// Which relation columns one column grant covers.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ColumnRule {
    /// Every live column except the one named.
    Except(&'static str),
    /// Only the column named.
    Only(&'static str),
}

/// One relation's runtime privileges: table-level privileges, which PostgreSQL also reports on
/// every column, and column-level grants.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RelationPrivileges {
    pub(crate) relation: &'static str,
    pub(crate) table: &'static [&'static str],
    pub(crate) columns: &'static [(&'static str, ColumnRule)],
}

/// The runtime role's complete privilege matrix in the configured schema.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimePrivileges {
    pub(crate) schema: &'static [&'static str],
    pub(crate) relations: &'static [RelationPrivileges],
}

/// The only code copy of the runtime privilege matrix. Migration 0006 grants exactly this and
/// carries the same list for its postcondition; a unit test compares the two. No sequence or
/// function privilege is listed, so the runtime role must hold none, and an object not listed
/// must show no privilege. A migration that adds or changes an object updates both.
pub(crate) const RUNTIME_PRIVILEGES: RuntimePrivileges = RuntimePrivileges {
    schema: &["USAGE"],
    relations: &[
        RelationPrivileges {
            relation: "exchanges",
            table: &["SELECT"],
            columns: &[
                ("INSERT", ColumnRule::Except("accepted")),
                ("UPDATE", ColumnRule::Only("accepted")),
            ],
        },
        RelationPrivileges {
            relation: "audit_events",
            table: &["SELECT", "INSERT"],
            columns: &[],
        },
        RelationPrivileges {
            relation: "acceptances",
            table: &["INSERT"],
            columns: &[],
        },
        RelationPrivileges {
            relation: "credit_transactions",
            table: &["SELECT", "INSERT"],
            columns: &[],
        },
        RelationPrivileges {
            relation: "credit_entries",
            table: &["SELECT", "INSERT"],
            columns: &[],
        },
        RelationPrivileges {
            relation: "_sqlx_migrations",
            table: &["SELECT"],
            columns: &[],
        },
    ],
};

/// One class of the runtime privilege rule that a role breaks. Only tests inspect it; startup
/// output never names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PrivilegeViolation {
    /// The role is a superuser, holds CREATEROLE, CREATEDB, REPLICATION, or BYPASSRLS, or does
    /// not exist.
    Attribute,
    /// The role is a member of some role.
    Membership,
    /// The role owns the current database.
    DatabaseOwner,
    /// The role owns some object anywhere in the cluster.
    ObjectOwner,
    /// The role or PUBLIC holds a parameter privilege.
    ParameterPrivilege,
    /// The role can create schemas in the current database.
    DatabaseCreate,
    /// The role has a per-role setting.
    RoleSetting,
    /// The schema privileges differ from the matrix, or the schema is missing.
    SchemaPrivilege,
    /// A relation's privileges differ from the matrix, or a listed relation is missing.
    TablePrivilege,
    /// A column's privileges differ from the matrix.
    ColumnPrivilege,
    /// The role holds a sequence privilege.
    SequencePrivilege,
    /// The role holds a function privilege.
    FunctionPrivilege,
    /// The role holds some privilege with grant option.
    GrantOption,
}

/// Every class of the runtime privilege rule that `role` breaks: part A, the principal, and
/// part B, effective privileges in the connection's current schema equal to
/// [`RUNTIME_PRIVILEGES`] with no grant option. An empty set means the role is acceptable.
///
/// It takes a connection, so tests can check state that a transaction on that connection has
/// not committed. It reads catalogs only and takes no lock.
///
/// # Errors
///
/// [`StoreError`] when a catalog cannot be read.
pub(crate) async fn runtime_privilege_violations(
    conn: &mut PgConnection,
    role: &str,
) -> Result<BTreeSet<PrivilegeViolation>, StoreError> {
    let mut violations = BTreeSet::new();
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(role)
            .fetch_one(&mut *conn)
            .await
            .map_err(map_sql)?;
    if !role_exists {
        violations.insert(PrivilegeViolation::Attribute);
        return Ok(violations);
    }
    let principal: (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
             COALESCE(role.rolsuper OR role.rolcreaterole OR role.rolcreatedb \
                 OR role.rolreplication OR role.rolbypassrls, TRUE), \
             EXISTS(SELECT 1 FROM pg_auth_members WHERE member = role.oid), \
             EXISTS(SELECT 1 FROM pg_database \
                 WHERE datname = current_database() AND datdba = role.oid), \
             EXISTS(SELECT 1 FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass \
                 AND refobjid = role.oid AND deptype = 'o'), \
             EXISTS(SELECT 1 FROM pg_parameter_acl, aclexplode(paracl) AS entry \
                 WHERE entry.grantee = 0 OR entry.grantee = role.oid), \
             COALESCE(has_database_privilege(role.oid, current_database(), 'CREATE'), TRUE), \
             EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole = role.oid) \
         FROM (SELECT $1::text AS name) AS wanted \
         LEFT JOIN pg_roles AS role ON role.rolname = wanted.name",
    )
    .bind(role)
    .fetch_one(&mut *conn)
    .await
    .map_err(map_sql)?;
    for (broken, violation) in [
        (principal.0, PrivilegeViolation::Attribute),
        (principal.1, PrivilegeViolation::Membership),
        (principal.2, PrivilegeViolation::DatabaseOwner),
        (principal.3, PrivilegeViolation::ObjectOwner),
        (principal.4, PrivilegeViolation::ParameterPrivilege),
        (principal.5, PrivilegeViolation::DatabaseCreate),
        (principal.6, PrivilegeViolation::RoleSetting),
    ] {
        if broken {
            violations.insert(violation);
        }
    }
    let schema: Option<String> = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&mut *conn)
        .await
        .map_err(map_sql)?;
    let Some(schema) = schema else {
        violations.insert(PrivilegeViolation::SchemaPrivilege);
        return Ok(violations);
    };

    let held: Vec<(String, String, String, String, bool)> = sqlx::query_as(HELD_PRIVILEGES)
        .bind(role)
        .bind(&schema)
        .fetch_all(&mut *conn)
        .await
        .map_err(map_sql)?;
    let live_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT relation.relname::text, attribute.attname::text \
         FROM pg_class AS relation \
         JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
         JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid \
             AND attribute.attnum > 0 AND NOT attribute.attisdropped \
         WHERE namespace.nspname = $1 AND relation.relkind IN ('r', 'v', 'm', 'f', 'p')",
    )
    .bind(&schema)
    .fetch_all(&mut *conn)
    .await
    .map_err(map_sql)?;

    let expected = expected_privileges(&RUNTIME_PRIVILEGES, &live_columns);
    let mut actual = BTreeSet::new();
    for (kind, object, column, privilege, grantable) in held {
        if grantable {
            violations.insert(PrivilegeViolation::GrantOption);
        }
        actual.insert((kind, object, column, privilege));
    }
    for (kind, ..) in actual.symmetric_difference(&expected) {
        violations.insert(match kind.as_str() {
            "schema" => PrivilegeViolation::SchemaPrivilege,
            "table" => PrivilegeViolation::TablePrivilege,
            "column" => PrivilegeViolation::ColumnPrivilege,
            "sequence" => PrivilegeViolation::SequencePrivilege,
            _ => PrivilegeViolation::FunctionPrivilege,
        });
    }
    Ok(violations)
}

/// One effective privilege: kind, object, column, and privilege, with empty text where a part
/// does not apply.
type HeldPrivilege = (String, String, String, String);

/// Every effective privilege `$1` holds on schema `$2` and its objects, with whether it is held
/// with grant option.
const HELD_PRIVILEGES: &str = "\
    WITH role AS (SELECT oid FROM pg_roles WHERE rolname = $1), \
    namespace AS (SELECT oid FROM pg_namespace WHERE nspname = $2), \
    relations AS ( \
        SELECT relation.oid, relation.relname::text AS name, relation.relkind \
        FROM pg_class AS relation, namespace \
        WHERE relation.relnamespace = namespace.oid \
            AND relation.relkind IN ('r', 'v', 'm', 'f', 'p', 'S')), \
    live_columns AS ( \
        SELECT relations.oid, relations.name, attribute.attnum, \
            attribute.attname::text AS column_name \
        FROM relations JOIN pg_attribute AS attribute ON attribute.attrelid = relations.oid \
            AND attribute.attnum > 0 AND NOT attribute.attisdropped \
        WHERE relations.relkind <> 'S') \
    SELECT 'schema', '', '', held, \
        has_schema_privilege(role.oid, namespace.oid, held || ' WITH GRANT OPTION') \
    FROM role, namespace, unnest(ARRAY['USAGE', 'CREATE']) AS held \
    WHERE has_schema_privilege(role.oid, namespace.oid, held) \
    UNION ALL \
    SELECT 'table', relations.name, '', held, \
        has_table_privilege(role.oid, relations.oid, held || ' WITH GRANT OPTION') \
    FROM role, relations, unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', \
        'REFERENCES', 'TRIGGER', 'MAINTAIN']) AS held \
    WHERE relations.relkind <> 'S' AND has_table_privilege(role.oid, relations.oid, held) \
    UNION ALL \
    SELECT 'column', live_columns.name, live_columns.column_name, held, \
        has_column_privilege(role.oid, live_columns.oid, live_columns.attnum, \
            held || ' WITH GRANT OPTION') \
    FROM role, live_columns, unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS held \
    WHERE has_column_privilege(role.oid, live_columns.oid, live_columns.attnum, held) \
    UNION ALL \
    SELECT 'sequence', relations.name, '', held, \
        has_sequence_privilege(role.oid, relations.oid, held || ' WITH GRANT OPTION') \
    FROM role, relations, unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS held \
    WHERE relations.relkind = 'S' AND has_sequence_privilege(role.oid, relations.oid, held) \
    UNION ALL \
    SELECT 'function', function_row.oid::text, '', 'EXECUTE', \
        has_function_privilege(role.oid, function_row.oid, 'EXECUTE WITH GRANT OPTION') \
    FROM role, namespace, pg_proc AS function_row \
    WHERE function_row.pronamespace = namespace.oid \
        AND has_function_privilege(role.oid, function_row.oid, 'EXECUTE')";

/// The effective privileges the matrix implies, given the live columns of each relation.
fn expected_privileges(
    matrix: &RuntimePrivileges,
    live_columns: &[(String, String)],
) -> BTreeSet<HeldPrivilege> {
    let mut expected = BTreeSet::new();
    for privilege in matrix.schema {
        expected.insert((
            "schema".to_owned(),
            String::new(),
            String::new(),
            (*privilege).to_owned(),
        ));
    }
    for relation in matrix.relations {
        for privilege in relation.table {
            expected.insert((
                "table".to_owned(),
                relation.relation.to_owned(),
                String::new(),
                (*privilege).to_owned(),
            ));
        }
        let columns = live_columns
            .iter()
            .filter(|(name, _)| name == relation.relation)
            .map(|(_, column)| column.as_str());
        for column in columns {
            let table_level = relation.table.iter().copied().filter(|privilege| {
                ["SELECT", "INSERT", "UPDATE", "REFERENCES"].contains(privilege)
            });
            let column_level = relation
                .columns
                .iter()
                .filter(|(_, rule)| match rule {
                    ColumnRule::Except(excluded) => column != *excluded,
                    ColumnRule::Only(included) => column == *included,
                })
                .map(|(privilege, _)| *privilege);
            for privilege in table_level.chain(column_level) {
                expected.insert((
                    "column".to_owned(),
                    relation.relation.to_owned(),
                    column.to_owned(),
                    privilege.to_owned(),
                ));
            }
        }
    }
    expected
}

/// How long a writability probe's result answers later callers.
const PROBE_TTL: Duration = Duration::from_secs(1);
/// How long a caller waits for a probe before reporting the store unavailable.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Ciphertext-only filesystem store rooted at one configured project-owned directory.
///
/// Its writability probe is single-flight and cached: at most one probe runs at a time, and a
/// result under a second old answers every caller, so unauthenticated readiness checks cannot
/// drive unbounded file creation and `fsync`.
pub struct FileDocumentStore {
    root: PathBuf,
    identity: RootIdentity,
    bounds: SweepBounds,
    #[cfg(feature = "test-support")]
    after_put_new: Option<PauseGate>,
    probe: Mutex<ProbeState>,
    probe_ttl: Duration,
    probe_timeout: Duration,
    hooks: ProbeHooks,
}

/// The last probe result, and a probe whose caller stopped waiting before it finished.
#[derive(Default)]
struct ProbeState {
    last: Option<(Instant, Result<(), StoreError>)>,
    running: Option<JoinHandle<Result<(), StoreError>>>,
}

/// Test observation points inside a probe; empty outside tests.
#[derive(Clone, Default)]
struct ProbeHooks {
    /// Probes started.
    #[cfg(test)]
    started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// While the flag is set, a probe waits after `sync_all` with its file present.
    #[cfg(test)]
    hold: Option<std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>>,
}

impl ProbeHooks {
    fn on_start(&self) {
        #[cfg(test)]
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn after_sync(&self) {
        #[cfg(test)]
        if let Some(hold) = &self.hold {
            let (held, released) = &**hold;
            let mut waiting = held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while *waiting {
                waiting = released
                    .wait(waiting)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }
}

impl FileDocumentStore {
    pub(crate) async fn new(root: PathBuf) -> Result<Self, StoreError> {
        Self::with_probe(root, PROBE_TTL, PROBE_TIMEOUT, ProbeHooks::default()).await
    }

    async fn with_probe(
        root: PathBuf,
        probe_ttl: Duration,
        probe_timeout: Duration,
        hooks: ProbeHooks,
    ) -> Result<Self, StoreError> {
        fs::create_dir_all(&root)
            .await
            .map_err(|_| StoreError::Permanent)?;
        let metadata = fs::symlink_metadata(&root)
            .await
            .map_err(|_| StoreError::Permanent)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(StoreError::Permanent);
        }
        let identity = RootIdentity::of(&root)?;
        Ok(Self {
            root,
            identity,
            bounds: SweepBounds::DEFAULT,
            #[cfg(feature = "test-support")]
            after_put_new: None,
            probe: Mutex::new(ProbeState::default()),
            probe_ttl,
            probe_timeout,
            hooks,
        })
    }

    /// The same store with shortened sweep bounds; only test support passes others.
    pub(crate) const fn with_bounds(mut self, bounds: SweepBounds) -> Self {
        self.bounds = bounds;
        self
    }

    /// The same store, pausing at `gate` after each `put_new` succeeds.
    #[cfg(feature = "test-support")]
    pub(crate) fn with_put_new_gate(mut self, gate: PauseGate) -> Self {
        self.after_put_new = Some(gate);
        self
    }

    /// The configured root.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The root's device and inode when the store was opened.
    pub(crate) const fn identity(&self) -> RootIdentity {
        self.identity
    }

    fn path(&self, object_id: &ObjectId) -> PathBuf {
        self.root.join(object_id.as_str())
    }
}

impl DocumentStore for FileDocumentStore {
    /// Returns a result under a second old if one exists. Otherwise, when an earlier probe is
    /// still running, reports [`StoreError::Transient`] without starting another; when none is,
    /// starts one and waits up to two seconds for it.
    ///
    /// # Cancellation
    ///
    /// The timeout, or dropping this future, ends only the wait. The probe runs to completion on
    /// a blocking thread and removes its file whenever the filesystem returns; the next caller
    /// collects its result.
    async fn probe_writable(&self) -> Result<(), StoreError> {
        let mut state = self.probe.lock().await;
        if let Some((at, result)) = state.last
            && at.elapsed() < self.probe_ttl
        {
            return result;
        }
        if let Some(running) = state.running.as_mut() {
            let result = if running.is_finished() {
                let finished = joined(running.await);
                state.running = None;
                finished
            } else {
                Err(StoreError::Transient)
            };
            state.last = Some((Instant::now(), result));
            return result;
        }
        let root = self.root.clone();
        let hooks = self.hooks.clone();
        let running = state.running.insert(tokio::task::spawn_blocking(move || {
            probe_once(&root, &hooks)
        }));
        let result = match tokio::time::timeout(self.probe_timeout, running).await {
            Ok(finished) => {
                state.running = None;
                joined(finished)
            }
            Err(_) => Err(StoreError::Transient),
        };
        state.last = Some((Instant::now(), result));
        result
    }

    async fn put_new(&self, object_id: &ObjectId, envelope: &[u8]) -> Result<(), StoreError> {
        let target = self.path(object_id);
        let temporary = self.root.join(format!(".{}.tmp", object_id.as_str()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(map_io_conflict)?;
        if let Err(error) = file.write_all(envelope).await {
            let _ = fs::remove_file(&temporary).await;
            return Err(map_io(error));
        }
        file.sync_all().await.map_err(map_io)?;
        drop(file);
        match fs::hard_link(&temporary, &target).await {
            Ok(()) => {
                fs::remove_file(&temporary).await.map_err(map_io)?;
                #[cfg(feature = "test-support")]
                if let Some(gate) = &self.after_put_new {
                    gate.pass().await;
                }
                Ok(())
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary).await;
                Err(map_io_conflict(error))
            }
        }
    }

    async fn get(&self, object_id: &ObjectId) -> Result<Vec<u8>, StoreError> {
        fs::read(self.path(object_id)).await.map_err(map_io)
    }

    async fn remove(&self, object_id: &ObjectId) -> Result<(), StoreError> {
        match fs::remove_file(self.path(object_id)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(map_io(error)),
        }
    }
}

/// Creates, writes, synchronizes, and removes one uniquely named `.ready-` file in `root`. Once
/// the file exists it is removed on every path. The name cannot collide with an object ID.
fn probe_once(root: &Path, hooks: &ProbeHooks) -> Result<(), StoreError> {
    use std::fmt::Write as _;

    hooks.on_start();
    let mut random = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(map_io)?;
    let mut name = String::with_capacity(39);
    name.push_str(".ready-");
    for byte in random {
        write!(&mut name, "{byte:02x}").map_err(|_| StoreError::Permanent)?;
    }
    let path = root.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(map_io)?;
    let written = file.write_all(b"ready").and_then(|()| file.sync_all());
    hooks.after_sync();
    drop(file);
    let removed = std::fs::remove_file(&path);
    written.map_err(map_io)?;
    removed.map_err(map_io)
}

fn joined(
    result: Result<Result<(), StoreError>, tokio::task::JoinError>,
) -> Result<(), StoreError> {
    result.map_err(|_| StoreError::Permanent)?
}

fn map_io(error: std::io::Error) -> StoreError {
    match error.kind() {
        std::io::ErrorKind::NotFound => StoreError::NotFound,
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => StoreError::Transient,
        _ => StoreError::Permanent,
    }
}

fn map_io_conflict(error: std::io::Error) -> StoreError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        StoreError::Conflict
    } else {
        map_io(error)
    }
}

/// PostgreSQL authoritative event, exchange, and balanced-credit adapter.
pub struct PgExchangeStore {
    pool: PgPool,
    /// The validated configured schema, which qualifies the reference read.
    schema: String,
    bounds: SweepBounds,
    #[cfg(feature = "test-support")]
    before_send_commit: Option<PauseGate>,
    #[cfg(feature = "test-support")]
    scan_fault: Option<ScanFault>,
}

impl PgExchangeStore {
    pub(crate) const fn new(pool: PgPool, schema: String) -> Self {
        Self {
            pool,
            schema,
            bounds: SweepBounds::DEFAULT,
            #[cfg(feature = "test-support")]
            before_send_commit: None,
            #[cfg(feature = "test-support")]
            scan_fault: None,
        }
    }

    /// The same store with shortened sweep bounds; only test support passes others.
    pub(crate) const fn with_bounds(mut self, bounds: SweepBounds) -> Self {
        self.bounds = bounds;
        self
    }

    /// The same store, pausing at `gate` inside each send transaction before its `COMMIT`.
    #[cfg(feature = "test-support")]
    pub(crate) fn with_commit_gate(mut self, gate: PauseGate) -> Self {
        self.before_send_commit = Some(gate);
        self
    }

    /// The same store, failing its reference read with `fault`.
    #[cfg(feature = "test-support")]
    pub(crate) const fn with_scan_fault(mut self, fault: Option<ScanFault>) -> Self {
        self.scan_fault = fault;
        self
    }

    #[cfg(feature = "test-support")]
    pub(crate) const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl ExchangeStore for PgExchangeStore {
    async fn find_by_idempotency(
        &self,
        sender: &WalletId,
        key: &IdempotencyKey,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        sqlx::query(
            "SELECT exchange_id, sender_wallet, recipient_wallet, document_id, document_version, \
             request_nonce, idempotency_key, schema_id, schema_version, object_id, \
             envelope_commitment, protected_hash, envelope_version, registry_sequence, \
             committed_at, accepted \
             FROM exchanges WHERE sender_wallet = $1 AND idempotency_key = $2",
        )
        .bind(sender.as_str())
        .bind(key.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql)?
        .map(row_to_exchange)
        .transpose()
    }

    async fn replay_exists(
        &self,
        sender: &WalletId,
        nonce: &RequestNonce,
        document_id: &DocumentId,
        version: DocumentVersion,
        recipient: &WalletId,
    ) -> Result<bool, StoreError> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM exchanges WHERE \
             sender_wallet = $1 AND (request_nonce = $2 OR \
             (document_id = $3 AND document_version = $4 AND recipient_wallet = $5)))",
        )
        .bind(sender.as_str())
        .bind(nonce.as_bytes().as_slice())
        .bind(document_id.as_str())
        .bind(to_i64(version.get())?)
        .bind(recipient.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sql)
    }

    async fn find(&self, exchange_id: &ExchangeId) -> Result<Option<ExchangeRecord>, StoreError> {
        sqlx::query(
            "SELECT exchange_id, sender_wallet, recipient_wallet, document_id, document_version, \
             request_nonce, idempotency_key, schema_id, schema_version, object_id, \
             envelope_commitment, protected_hash, envelope_version, registry_sequence, \
             committed_at, accepted \
             FROM exchanges WHERE exchange_id = $1",
        )
        .bind(exchange_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql)?
        .map(row_to_exchange)
        .transpose()
    }

    async fn commit_send<I: EventIntegrity>(
        &self,
        record: &ExchangeRecord,
        event: EventDraft,
        integrity: &I,
        pending_limit: u32,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sql)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
            .bind(record.sender.as_str())
            .bind(record.recipient.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(map_sql)?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM exchanges WHERE sender_wallet = $1 \
             AND recipient_wallet = $2 AND accepted = FALSE",
        )
        .bind(record.sender.as_str())
        .bind(record.recipient.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sql)?;
        if pending >= i64::from(pending_limit) {
            return Err(StoreError::PendingLimit);
        }
        sqlx::query(
            "INSERT INTO exchanges (exchange_id, sender_wallet, recipient_wallet, document_id, \
             document_version, request_nonce, idempotency_key, schema_id, schema_version, \
             object_id, envelope_commitment, protected_hash, envelope_version, registry_sequence, \
             committed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(record.exchange_id.as_str())
        .bind(record.sender.as_str())
        .bind(record.recipient.as_str())
        .bind(record.document_id.as_str())
        .bind(to_i64(record.document_version.get())?)
        .bind(record.request_nonce.as_bytes().as_slice())
        .bind(record.idempotency_key.as_str())
        .bind(&record.schema_id)
        .bind(&record.schema_version)
        .bind(record.object_id.as_str())
        .bind(record.envelope_commitment.as_slice())
        .bind(record.protected_hash.as_slice())
        .bind(i32::try_from(record.envelope_version).map_err(|_| StoreError::Invariant)?)
        .bind(to_i64(record.registry_sequence)?)
        .bind(record.committed_at.unix_seconds())
        .execute(&mut *transaction)
        .await
        .map_err(map_sql)?;
        append_event(&mut transaction, event, integrity).await?;
        #[cfg(feature = "test-support")]
        if let Some(gate) = &self.before_send_commit {
            gate.pass().await;
        }
        transaction.commit().await.map_err(map_sql)
    }

    async fn commit_acceptance<I: EventIntegrity>(
        &self,
        exchange_id: &ExchangeId,
        key: &IdempotencyKey,
        credit: &CreditPosting,
        event: EventDraft,
        integrity: &I,
    ) -> Result<AcceptanceOutcome, StoreError> {
        if credit.amount != 1 {
            return Err(StoreError::Invariant);
        }
        let mut transaction = self.pool.begin().await.map_err(map_sql)?;
        let accepted = sqlx::query_scalar::<_, bool>(
            "SELECT accepted FROM exchanges WHERE exchange_id = $1 FOR UPDATE",
        )
        .bind(exchange_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sql)?
        .ok_or(StoreError::NotFound)?;
        if accepted {
            transaction.commit().await.map_err(map_sql)?;
            return Ok(AcceptanceOutcome::AlreadyAccepted);
        }
        sqlx::query(
            "INSERT INTO acceptances (exchange_id, recipient_wallet, idempotency_key) \
             SELECT exchange_id, recipient_wallet, $2 FROM exchanges WHERE exchange_id = $1",
        )
        .bind(exchange_id.as_str())
        .bind(key.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(map_sql)?;
        sqlx::query("UPDATE exchanges SET accepted = TRUE WHERE exchange_id = $1")
            .bind(exchange_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(map_sql)?;
        sqlx::query(
            "INSERT INTO credit_transactions (eligibility_key, exchange_id) VALUES ($1, $2)",
        )
        .bind(&credit.eligibility_key)
        .bind(exchange_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(map_sql)?;
        sqlx::query(
            "INSERT INTO credit_entries (eligibility_key, account_id, amount) \
             VALUES ($1, $3, -1), ($1, $2, 1)",
        )
        .bind(&credit.eligibility_key)
        .bind(credit.wallet.as_str())
        .bind(ISSUANCE_ACCOUNT)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql)?;
        append_event(&mut transaction, event, integrity).await?;
        transaction.commit().await.map_err(map_sql)?;
        Ok(AcceptanceOutcome::Recorded)
    }

    async fn pending_inbox(
        &self,
        wallet: &WalletId,
        limit: u32,
    ) -> Result<Vec<ExchangeId>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT exchange_id FROM exchanges WHERE recipient_wallet = $1 AND accepted = FALSE \
             ORDER BY exchange_id LIMIT $2",
        )
        .bind(wallet.as_str())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sql)?
        .into_iter()
        .map(|id| ExchangeId::new(id).map_err(|_| StoreError::Invariant))
        .collect()
    }

    async fn object_referenced(&self, object_id: &ObjectId) -> Result<bool, StoreError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM exchanges WHERE object_id = $1)")
            .bind(object_id.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(map_sql)
    }

    async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(map_sql)
    }
}

impl AuditEventStore for PgExchangeStore {
    async fn page(&self, request: AuditReadRequest) -> Result<AuditStoredPage, AuditReadError> {
        if !(1..=500).contains(&request.limit) {
            return Err(AuditReadError::Invariant);
        }
        let mut transaction = self.pool.begin().await.map_err(map_audit_sql)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(map_audit_sql)?;

        let snapshot = match request.snapshot {
            Some(snapshot) => {
                match snapshot.head() {
                    None => {
                        let exists: bool =
                            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events)")
                                .fetch_one(&mut *transaction)
                                .await
                                .map_err(map_audit_sql)?;
                        if exists {
                            return Err(AuditReadError::SnapshotChanged);
                        }
                    }
                    Some(expected) => {
                        let row = sqlx::query(
                            "SELECT event_hash, signature FROM audit_events WHERE sequence = $1",
                        )
                        .bind(to_i64(expected.sequence).map_err(|_| AuditReadError::Invariant)?)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(map_audit_sql)?
                        .ok_or(AuditReadError::SnapshotChanged)?;
                        let hash = exact::<32>(row.try_get("event_hash").map_err(map_audit_sql)?)
                            .map_err(|_| AuditReadError::Invariant)?;
                        let signature =
                            exact::<64>(row.try_get("signature").map_err(map_audit_sql)?)
                                .map_err(|_| AuditReadError::Invariant)?;
                        if hash != expected.event_hash || signature != expected.signature {
                            return Err(AuditReadError::SnapshotChanged);
                        }
                    }
                }
                snapshot
            }
            None => select_tail(&mut transaction).await?,
        };

        if request.after_sequence > snapshot.event_count() {
            return Err(AuditReadError::SnapshotChanged);
        }
        let previous_hash = if request.after_sequence == 0 {
            [0; 32]
        } else {
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT event_hash FROM audit_events WHERE sequence = $1",
            )
            .bind(to_i64(request.after_sequence).map_err(|_| AuditReadError::Invariant)?)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_audit_sql)?
            .ok_or(AuditReadError::SnapshotChanged)
            .and_then(|bytes| exact(bytes).map_err(|_| AuditReadError::Invariant))?
        };
        let fetch_limit = i64::from(request.limit)
            .checked_add(1)
            .ok_or(AuditReadError::Invariant)?;
        let rows = sqlx::query(
            "SELECT sequence, kind, exchange_id, object_id, commitment, envelope_version, \
             protected_hash, sender_wallet, recipient_wallet, document_id, document_version, \
             registry_sequence, committed_at, previous_hash, event_hash, signature \
             FROM audit_events WHERE sequence > $1 AND sequence <= $2 \
             ORDER BY sequence LIMIT $3",
        )
        .bind(to_i64(request.after_sequence).map_err(|_| AuditReadError::Invariant)?)
        .bind(to_i64(snapshot.event_count()).map_err(|_| AuditReadError::Invariant)?)
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_audit_sql)?;
        let mut events = rows
            .into_iter()
            .map(|row| row_to_event(row).map_err(|_| AuditReadError::Invariant))
            .collect::<Result<Vec<_>, _>>()?;
        let limit = usize::try_from(request.limit).map_err(|_| AuditReadError::Invariant)?;
        let has_more = events.len() > limit;
        if has_more {
            events.truncate(limit);
        }
        if let Some(first) = events.first() {
            if first.sequence != request.after_sequence.saturating_add(1)
                || first.previous_hash != previous_hash
            {
                return Err(AuditReadError::SnapshotChanged);
            }
        } else if request.after_sequence != snapshot.event_count() {
            return Err(AuditReadError::SnapshotChanged);
        }
        transaction.commit().await.map_err(map_audit_sql)?;
        Ok(AuditStoredPage {
            snapshot,
            events,
            has_more,
        })
    }

    async fn credit_snapshot(
        &self,
        max_transactions: u32,
    ) -> Result<AuditCreditSnapshot, AuditReadError> {
        let max_transactions = i64::from(max_transactions);
        let max_entries = max_transactions
            .checked_mul(2)
            .ok_or(AuditReadError::Invariant)?;
        let mut transaction = self.pool.begin().await.map_err(map_audit_sql)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(map_audit_sql)?;
        let snapshot = select_tail(&mut transaction).await?;
        let (transactions, entries): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM credit_transactions), \
             (SELECT COUNT(*) FROM credit_entries)",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_audit_sql)?;
        if transactions > max_transactions || entries > max_entries {
            return Err(AuditReadError::Exhausted);
        }
        // Every joined row is a transaction, an entry, or both; more rows than both bounds
        // together can only come from rows sharing one key, and are refused the same way.
        let row_limit = max_transactions
            .checked_add(max_entries)
            .ok_or(AuditReadError::Invariant)?;
        let rows: Vec<LedgerRow> = sqlx::query_as(
            "SELECT credit.ctid::text, left(credit.eligibility_key, 129), \
             left(credit.exchange_id, 129), entry.ctid IS NOT NULL, \
             left(entry.eligibility_key, 129), \
             left(entry.account_id, 129), entry.amount \
             FROM credit_transactions AS credit \
             FULL OUTER JOIN credit_entries AS entry \
                 ON entry.eligibility_key = credit.eligibility_key \
             ORDER BY COALESCE(credit.eligibility_key, entry.eligibility_key), credit.ctid, \
                 entry.account_id, entry.amount \
             LIMIT $1",
        )
        .bind(row_limit.saturating_add(1))
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_audit_sql)?;
        if i64::try_from(rows.len()).map_or(true, |count| count > row_limit) {
            return Err(AuditReadError::Exhausted);
        }
        transaction.commit().await.map_err(map_audit_sql)?;
        Ok(AuditCreditSnapshot {
            snapshot,
            transactions: group_ledger(rows),
        })
    }
}

/// The current chain tail, inside the caller's snapshot transaction.
async fn select_tail(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<AuditSnapshot, AuditReadError> {
    let tail = sqlx::query(
        "SELECT sequence, event_hash, signature FROM audit_events \
         ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_audit_sql)?;
    match tail {
        None => AuditSnapshot::new(0, None).map_err(|_| AuditReadError::Invariant),
        Some(row) => {
            let sequence = from_i64(row.try_get("sequence").map_err(map_audit_sql)?)
                .map_err(|_| AuditReadError::Invariant)?;
            let head = Checkpoint {
                sequence,
                event_hash: exact(row.try_get("event_hash").map_err(map_audit_sql)?)
                    .map_err(|_| AuditReadError::Invariant)?,
                signature: exact(row.try_get("signature").map_err(map_audit_sql)?)
                    .map_err(|_| AuditReadError::Invariant)?,
            };
            AuditSnapshot::new(sequence, Some(head)).map_err(|_| AuditReadError::Invariant)
        }
    }
}

/// One row of the credit ledger read: a transaction row, an entry, or both. It holds the
/// transaction's row identity, key, and exchange; whether an entry row is present; and the
/// entry's key, account, and amount. Text values are truncated to 129 characters, one more than
/// any valid key or identifier can reach.
type LedgerRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    Option<i64>,
);

/// Groups the ordered ledger rows: one transaction per stored transaction row, with its
/// entries, and one per eligibility key for entries that have no transaction row.
fn group_ledger(rows: Vec<LedgerRow>) -> Vec<CreditLedgerTransaction> {
    /// A stored transaction row, or the key of entries without one.
    #[derive(PartialEq, Eq)]
    enum Group {
        Transaction(String),
        Orphaned(Option<String>),
    }

    let mut grouped: Vec<(Group, CreditLedgerTransaction)> = Vec::new();
    for (
        transaction_row,
        transaction_key,
        exchange_id,
        entry_present,
        entry_key,
        account,
        amount,
    ) in rows
    {
        let (group, eligibility_key, exchange_id) = match transaction_row {
            Some(row) => (
                Group::Transaction(row),
                transaction_key,
                Some(exchange_id.unwrap_or_default()),
            ),
            None => (Group::Orphaned(entry_key.clone()), entry_key.clone(), None),
        };
        if grouped.last().is_none_or(|(last, _)| *last != group) {
            grouped.push((
                group,
                CreditLedgerTransaction {
                    eligibility_key: eligibility_key.unwrap_or_default(),
                    exchange_id,
                    entries: Vec::new(),
                },
            ));
        }
        // A stored NULL never matches an expected entry, so it is read as a value that cannot.
        if let (true, Some((_, current))) = (entry_present, grouped.last_mut()) {
            current.entries.push(CreditLedgerEntry {
                account: account.unwrap_or_default(),
                amount: amount.unwrap_or(0),
            });
        }
    }
    grouped
        .into_iter()
        .map(|(_, transaction)| transaction)
        .collect()
}

async fn append_event<I: EventIntegrity>(
    transaction: &mut Transaction<'_, Postgres>,
    draft: EventDraft,
    integrity: &I,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext(current_schema()), 17331)")
        .execute(&mut **transaction)
        .await
        .map_err(map_sql)?;
    let prior =
        sqlx::query("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sql)?;
    let (sequence, previous_hash) = prior.map_or(Ok((1, [0; 32])), |row| {
        let sequence = from_i64(row.try_get("sequence").map_err(map_sql)?)?
            .checked_add(1)
            .ok_or(StoreError::Invariant)?;
        Ok((
            sequence,
            exact::<32>(row.try_get("event_hash").map_err(map_sql)?)?,
        ))
    })?;
    let event_hash = AuditEvent::hash_for(&draft, sequence, &previous_hash)
        .map_err(|_| StoreError::Invariant)?;
    let signature = integrity
        .sign(&event_signature_input(&event_hash))
        .map_err(|_| StoreError::Invariant)?;
    let event = AuditEvent::assemble(draft, sequence, previous_hash, signature)
        .map_err(|_| StoreError::Invariant)?;
    sqlx::query(
        "INSERT INTO audit_events (sequence, kind, exchange_id, object_id, commitment, \
         envelope_version, protected_hash, sender_wallet, recipient_wallet, document_id, \
         document_version, registry_sequence, committed_at, previous_hash, event_hash, signature) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    )
    .bind(to_i64(event.sequence)?)
    .bind(event.draft.kind.as_str())
    .bind(event.draft.exchange_id.as_str())
    .bind(event.draft.object_id.as_str())
    .bind(event.draft.envelope_commitment.as_slice())
    .bind(i32::try_from(event.draft.envelope_version).map_err(|_| StoreError::Invariant)?)
    .bind(event.draft.protected_hash.as_slice())
    .bind(event.draft.sender.as_str())
    .bind(event.draft.recipient.as_str())
    .bind(event.draft.document_id.as_str())
    .bind(to_i64(event.draft.document_version.get())?)
    .bind(to_i64(event.draft.registry_sequence)?)
    .bind(event.draft.committed_at.unix_seconds())
    .bind(event.previous_hash.as_slice())
    .bind(event.event_hash.as_slice())
    .bind(event.signature.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(map_sql)?;
    Ok(())
}

fn row_to_exchange(row: sqlx::postgres::PgRow) -> Result<ExchangeRecord, StoreError> {
    Ok(ExchangeRecord {
        exchange_id: ExchangeId::new(row.try_get::<String, _>("exchange_id").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        sender: WalletId::new(row.try_get::<String, _>("sender_wallet").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        recipient: WalletId::new(
            row.try_get::<String, _>("recipient_wallet")
                .map_err(map_sql)?,
        )
        .map_err(|_| StoreError::Invariant)?,
        document_id: DocumentId::new(row.try_get::<String, _>("document_id").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        document_version: DocumentVersion::new(from_i64(
            row.try_get("document_version").map_err(map_sql)?,
        )?)
        .map_err(|_| StoreError::Invariant)?,
        request_nonce: RequestNonce::new(exact(row.try_get("request_nonce").map_err(map_sql)?)?),
        idempotency_key: IdempotencyKey::new(
            row.try_get::<String, _>("idempotency_key")
                .map_err(map_sql)?,
        )
        .map_err(|_| StoreError::Invariant)?,
        schema_id: row.try_get("schema_id").map_err(map_sql)?,
        schema_version: row.try_get("schema_version").map_err(map_sql)?,
        object_id: ObjectId::new(row.try_get::<String, _>("object_id").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        envelope_commitment: exact(row.try_get("envelope_commitment").map_err(map_sql)?)?,
        protected_hash: exact(row.try_get("protected_hash").map_err(map_sql)?)?,
        envelope_version: u32::try_from(
            row.try_get::<i32, _>("envelope_version").map_err(map_sql)?,
        )
        .map_err(|_| StoreError::Invariant)?,
        registry_sequence: from_i64(row.try_get("registry_sequence").map_err(map_sql)?)?,
        committed_at: committed_at(&row)?,
        accepted: row.try_get("accepted").map_err(map_sql)?,
    })
}

fn row_to_event(row: sqlx::postgres::PgRow) -> Result<AuditEvent, StoreError> {
    let draft = EventDraft {
        kind: EventKind::from_stored(&row.try_get::<String, _>("kind").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        exchange_id: ExchangeId::new(row.try_get::<String, _>("exchange_id").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        object_id: ObjectId::new(row.try_get::<String, _>("object_id").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        envelope_commitment: exact(row.try_get("commitment").map_err(map_sql)?)?,
        envelope_version: u32::try_from(
            row.try_get::<i32, _>("envelope_version").map_err(map_sql)?,
        )
        .map_err(|_| StoreError::Invariant)?,
        protected_hash: exact(row.try_get("protected_hash").map_err(map_sql)?)?,
        sender: WalletId::new(row.try_get::<String, _>("sender_wallet").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        recipient: WalletId::new(
            row.try_get::<String, _>("recipient_wallet")
                .map_err(map_sql)?,
        )
        .map_err(|_| StoreError::Invariant)?,
        document_id: DocumentId::new(row.try_get::<String, _>("document_id").map_err(map_sql)?)
            .map_err(|_| StoreError::Invariant)?,
        document_version: DocumentVersion::new(from_i64(
            row.try_get("document_version").map_err(map_sql)?,
        )?)
        .map_err(|_| StoreError::Invariant)?,
        registry_sequence: from_i64(row.try_get("registry_sequence").map_err(map_sql)?)?,
        committed_at: committed_at(&row)?,
    };
    Ok(AuditEvent {
        sequence: from_i64(row.try_get("sequence").map_err(map_sql)?)?,
        draft,
        previous_hash: exact(row.try_get("previous_hash").map_err(map_sql)?)?,
        event_hash: exact(row.try_get("event_hash").map_err(map_sql)?)?,
        signature: exact(row.try_get("signature").map_err(map_sql)?)?,
    })
}

/// The stored commit time, exactly as written; never a clock reading.
fn committed_at(row: &sqlx::postgres::PgRow) -> Result<Timestamp, StoreError> {
    let seconds: i64 = row.try_get("committed_at").map_err(map_sql)?;
    if seconds < 0 {
        return Err(StoreError::Invariant);
    }
    Ok(Timestamp::from_unix_seconds(seconds))
}

fn exact<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Invariant)
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Invariant)
}

fn from_i64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Invariant)
}

fn map_sql(error: sqlx::Error) -> StoreError {
    match &error {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
            StoreError::Conflict
        }
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
            StoreError::Transient
        }
        _ => StoreError::Permanent,
    }
}

fn map_audit_sql(error: sqlx::Error) -> AuditReadError {
    match map_sql(error) {
        StoreError::Transient => AuditReadError::Transient,
        StoreError::Permanent => AuditReadError::Permanent,
        _ => AuditReadError::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[cfg(feature = "test-support")]
    use sqlx::SqlSafeStr as _;

    use super::*;

    /// Every field SQLx compares or records, for each migration in order.
    fn migration_fields(
        migrator: &Migrator,
    ) -> Vec<(i64, String, String, Vec<u8>, MigrationType, bool)> {
        migrator
            .iter()
            .map(|migration| {
                (
                    migration.version,
                    migration.description.to_string(),
                    migration.sql.as_str().to_owned(),
                    migration.checksum.to_vec(),
                    migration.migration_type,
                    migration.no_tx,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn embedded_migrations_match_the_directory() {
        let embedded = Migrator::new(EmbeddedMigrations)
            .await
            .expect("embedded migrations");
        let directory = Migrator::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations"))
            .await
            .expect("migration directory");
        // A file left off the embedded list, or listed out of order, fails here.
        assert_eq!(migration_fields(&embedded), migration_fields(&directory));
        assert_eq!(
            embedded
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn migration_0006_postcondition_lists_the_runtime_privilege_matrix() {
        let mut rendered = Vec::new();
        for privilege in RUNTIME_PRIVILEGES.schema {
            rendered.push(format!("('schema', '', '', '{privilege}')"));
        }
        for relation in RUNTIME_PRIVILEGES.relations {
            let name = relation.relation;
            for privilege in relation.table {
                rendered.push(format!("('table', '{name}', '', '{privilege}')"));
            }
            for (privilege, rule) in relation.columns {
                let (kind, columns) = match rule {
                    ColumnRule::Except(columns) => ("columns except", columns),
                    ColumnRule::Only(columns) => ("columns only", columns),
                };
                rendered.push(format!("('{kind}', '{name}', '{columns}', '{privilege}')"));
            }
        }
        let (version, _, sql) = MIGRATIONS[5];
        assert_eq!(version, 6);
        let listed = sql
            .split("-- runtime privilege matrix")
            .nth(1)
            .and_then(|rest| rest.split("-- end of runtime privilege matrix").next())
            .expect("matrix block")
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('('))
            .map(|line| line.trim_end_matches(',').to_owned())
            .collect::<Vec<_>>();
        assert_eq!(listed, rendered);
    }

    #[test]
    fn ledger_rows_group_by_stored_transaction_and_orphaned_key() {
        let text = |value: &str| Some(value.to_owned());
        let rows: Vec<LedgerRow> = vec![
            // One transaction with two entries.
            (
                text("(0,1)"),
                text("acceptance:a"),
                text("exc_a"),
                true,
                text("acceptance:a"),
                text("issuance"),
                Some(-1),
            ),
            (
                text("(0,1)"),
                text("acceptance:a"),
                text("exc_a"),
                true,
                text("acceptance:a"),
                text("wal_a"),
                Some(1),
            ),
            // A second row with the same key is its own transaction, with its own entry.
            (
                text("(0,2)"),
                text("acceptance:a"),
                text("exc_b"),
                true,
                text("acceptance:a"),
                text("wal_a"),
                Some(1),
            ),
            // A transaction with no entries.
            (
                text("(0,3)"),
                text("acceptance:b"),
                text("exc_c"),
                false,
                None,
                None,
                None,
            ),
            // Entries with no transaction, one holding stored NULLs.
            (
                None,
                None,
                None,
                true,
                text("orphan"),
                text("wal_a"),
                Some(1),
            ),
            (None, None, None, true, text("orphan"), None, None),
            // An entry whose key is NULL.
            (None, None, None, true, None, text("wal_a"), Some(1)),
        ];
        let grouped = group_ledger(rows);
        let summary = grouped
            .iter()
            .map(|transaction| {
                (
                    transaction.eligibility_key.as_str(),
                    transaction.exchange_id.as_deref(),
                    transaction
                        .entries
                        .iter()
                        .map(|entry| (entry.account.as_str(), entry.amount))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                (
                    "acceptance:a",
                    Some("exc_a"),
                    vec![("issuance", -1), ("wal_a", 1)]
                ),
                ("acceptance:a", Some("exc_b"), vec![("wal_a", 1)]),
                ("acceptance:b", Some("exc_c"), vec![]),
                ("orphan", None, vec![("wal_a", 1), ("", 0)]),
                ("", None, vec![("wal_a", 1)]),
            ]
        );
    }

    fn probe_root(line: u32) -> PathBuf {
        std::env::temp_dir().join(format!("docchain_probe_{}_{line}", std::process::id()))
    }

    /// `.ready-` files currently in `root`.
    fn ready_files(root: &Path) -> usize {
        std::fs::read_dir(root)
            .expect("root listing")
            .filter(|entry| {
                entry
                    .as_ref()
                    .expect("root entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ready-")
            })
            .count()
    }

    /// Waits up to five seconds for `condition`.
    async fn eventually(condition: impl Fn() -> bool) -> bool {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        condition()
    }

    #[tokio::test]
    async fn probe_fails_when_the_root_is_gone() {
        let root = probe_root(line!());
        // No cache, so the second probe runs after the root is removed.
        let store = FileDocumentStore::with_probe(
            root.clone(),
            Duration::ZERO,
            PROBE_TIMEOUT,
            ProbeHooks::default(),
        )
        .await
        .expect("document store");
        assert_eq!(store.probe_writable().await, Ok(()));
        // The probe leaves nothing behind.
        assert_eq!(std::fs::read_dir(&root).expect("root listing").count(), 0);
        std::fs::remove_dir_all(&root).expect("remove root");
        assert!(store.probe_writable().await.is_err());
    }

    #[tokio::test]
    async fn probe_is_single_flight_and_cached() {
        let root = probe_root(line!());
        let store = std::sync::Arc::new(
            FileDocumentStore::new(root.clone())
                .await
                .expect("document store"),
        );
        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let store = std::sync::Arc::clone(&store);
            calls.spawn(async move { store.probe_writable().await });
        }
        while let Some(result) = calls.join_next().await {
            assert_eq!(result.expect("probe call"), Ok(()));
        }
        let started = || {
            store
                .hooks
                .started
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        assert_eq!(started(), 1);
        assert_eq!(ready_files(&root), 0);

        tokio::time::sleep(PROBE_TTL + Duration::from_millis(100)).await;
        assert_eq!(store.probe_writable().await, Ok(()));
        assert_eq!(started(), 2);
        assert_eq!(ready_files(&root), 0);
        std::fs::remove_dir_all(&root).expect("remove root");
    }

    #[tokio::test]
    async fn probe_timeout_removes_its_file() {
        let root = probe_root(line!());
        let hold = std::sync::Arc::new((std::sync::Mutex::new(true), std::sync::Condvar::new()));
        let hooks = ProbeHooks {
            hold: Some(std::sync::Arc::clone(&hold)),
            ..ProbeHooks::default()
        };
        let store = FileDocumentStore::with_probe(
            root.clone(),
            Duration::ZERO,
            Duration::from_millis(50),
            hooks.clone(),
        )
        .await
        .expect("document store");

        assert_eq!(store.probe_writable().await, Err(StoreError::Transient));
        assert!(
            eventually(|| ready_files(&root) == 1).await,
            "the held probe's file"
        );
        // A caller during the hold starts nothing.
        assert_eq!(store.probe_writable().await, Err(StoreError::Transient));
        assert_eq!(ready_files(&root), 1);
        assert_eq!(hooks.started.load(std::sync::atomic::Ordering::SeqCst), 1);

        *hold.0.lock().expect("hold flag") = false;
        hold.1.notify_all();
        assert!(
            eventually(|| ready_files(&root) == 0).await,
            "the probe removes its file once the filesystem returns"
        );
        std::fs::remove_dir_all(&root).expect("remove root");
    }

    #[cfg(feature = "test-support")]
    mod database {
        use sha2::{Digest as _, Sha384};

        use super::*;
        use crate::harness::{DocchainService, FixtureFiles, ServiceError};

        /// `_sqlx_migrations` as text, so every column, `installed_on` included, is comparable.
        async fn recorded(pool: &PgPool) -> Vec<(i64, String, String, bool, Vec<u8>)> {
            sqlx::query_as(
                "SELECT version, description, installed_on::text, success, checksum \
                 FROM _sqlx_migrations ORDER BY version",
            )
            .fetch_all(pool)
            .await
            .expect("recorded migrations")
        }

        /// Applies every pending migration on one connection of `pool`, and closes that
        /// connection after a failure, so SQLx's database-wide migration lock is released.
        async fn migrate(pool: &PgPool) -> Result<(), StoreError> {
            let mut conn = pool.acquire().await.expect("connection");
            let migrated = migrate_schema(&mut conn).await;
            if migrated.is_err() {
                conn.close()
                    .await
                    .expect("close the failed migration connection");
            }
            migrated
        }

        /// A new fixture whose schema the owner created, with the owner's pool.
        async fn created() -> (FixtureFiles, PgPool) {
            let fixture = FixtureFiles::write().expect("fixture files");
            let owner = fixture.owner_pool().await.expect("owner pool");
            fixture.create_schema(&owner).await.expect("schema");
            (fixture, owner)
        }

        /// A fixture migrated by the owner, with the owner's pool.
        async fn migrated() -> (FixtureFiles, PgPool) {
            let (fixture, owner) = created().await;
            migrate(&owner).await.expect("migrations");
            (fixture, owner)
        }

        #[tokio::test]
        async fn migrations_apply_from_empty_then_rerun_as_no_op() {
            let (_fixture, pool) = migrated().await;
            let first = recorded(&pool).await;
            assert_eq!(
                first
                    .iter()
                    .map(|(version, description, _, success, checksum)| {
                        (*version, description.clone(), *success, checksum.clone())
                    })
                    .collect::<Vec<_>>(),
                MIGRATIONS
                    .iter()
                    .map(|(version, description, sql)| {
                        (
                            *version,
                            (*description).to_owned(),
                            true,
                            Sha384::digest(sql.as_bytes()).to_vec(),
                        )
                    })
                    .collect::<Vec<_>>()
            );

            assert_eq!(migrate(&pool).await, Ok(()));
            assert_eq!(recorded(&pool).await, first);
        }

        #[derive(Debug)]
        struct EditedFirstMigration;

        impl MigrationSource<'static> for EditedFirstMigration {
            fn resolve(
                self,
            ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>>
            {
                Box::pin(async {
                    Ok(MIGRATIONS
                        .iter()
                        .map(|(version, description, sql)| {
                            let mut sql = (*sql).to_owned();
                            if *version == 1 {
                                sql.push('\n');
                            }
                            Migration::new(
                                *version,
                                Cow::Borrowed(*description),
                                MigrationType::Simple,
                                sqlx::AssertSqlSafe(sql).into_sql_str(),
                                false,
                            )
                        })
                        .collect())
                })
            }
        }

        #[tokio::test]
        async fn an_edited_applied_migration_is_refused() {
            let (_fixture, pool) = migrated().await;
            let before = recorded(&pool).await;

            let edited = Migrator::new(EditedFirstMigration)
                .await
                .expect("edited migrations");
            assert!(matches!(
                edited.run(&pool).await,
                Err(sqlx::migrate::MigrateError::VersionMismatch(1))
            ));
            assert_eq!(recorded(&pool).await, before);

            sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 2")
                .bind(vec![0_u8; 48])
                .execute(&pool)
                .await
                .expect("tamper with the recorded checksum");
            let tampered = recorded(&pool).await;
            assert_eq!(migrate(&pool).await, Err(StoreError::Permanent));
            assert_eq!(recorded(&pool).await, tampered);
        }

        #[tokio::test]
        async fn migration_state_reports_current_pending_and_mismatch() {
            let (fixture, owner) = created().await;
            let runtime = fixture.runtime_pool().await.expect("runtime pool");
            let state = |pool: PgPool| {
                let schema = fixture.schema.clone();
                async move {
                    let mut conn = pool.acquire().await.expect("connection");
                    migration_state(&mut conn, &schema).await
                }
            };
            // Unmigrated: the runtime role has no USAGE, and the owner has no ledger.
            assert_eq!(state(runtime.clone()).await, Ok(MigrationState::Pending));
            assert_eq!(state(owner.clone()).await, Ok(MigrationState::Pending));
            migrate(&owner).await.expect("migrations");
            assert_eq!(state(runtime.clone()).await, Ok(MigrationState::Current));

            sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 2")
                .bind(vec![0_u8; 48])
                .execute(&owner)
                .await
                .expect("tamper with the recorded checksum");
            assert_eq!(state(runtime.clone()).await, Ok(MigrationState::Mismatch));
            sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 2")
                .bind(Sha384::digest(MIGRATIONS[1].2.as_bytes()).to_vec())
                .execute(&owner)
                .await
                .expect("restore the recorded checksum");
            sqlx::query("UPDATE _sqlx_migrations SET success = FALSE WHERE version = 3")
                .execute(&owner)
                .await
                .expect("mark a version failed");
            assert_eq!(state(runtime.clone()).await, Ok(MigrationState::Mismatch));
            sqlx::query("UPDATE _sqlx_migrations SET success = TRUE WHERE version = 3")
                .execute(&owner)
                .await
                .expect("restore the version");
            sqlx::query(
                "INSERT INTO _sqlx_migrations \
                 (version, description, success, checksum, execution_time) \
                 VALUES (99, 'unknown', TRUE, '\\x00', 0)",
            )
            .execute(&owner)
            .await
            .expect("record an unknown version");
            assert_eq!(state(runtime.clone()).await, Ok(MigrationState::Mismatch));
            sqlx::query("DELETE FROM _sqlx_migrations WHERE version IN (6, 99)")
                .execute(&owner)
                .await
                .expect("remove the newest version");
            assert_eq!(state(runtime).await, Ok(MigrationState::Pending));
        }

        #[tokio::test]
        async fn migration_scopes_the_document_tuple_to_the_sender() {
            let (_fixture, pool) = migrated().await;
            let unique: Vec<Vec<String>> = sqlx::query_scalar(
                "SELECT array_agg(attribute.attname::text ORDER BY key.position) \
                 FROM pg_constraint AS constraint_row \
                 JOIN pg_class AS relation ON relation.oid = constraint_row.conrelid \
                 JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                 CROSS JOIN LATERAL unnest(constraint_row.conkey) \
                     WITH ORDINALITY AS key(number, position) \
                 JOIN pg_attribute AS attribute \
                     ON attribute.attrelid = relation.oid AND attribute.attnum = key.number \
                 WHERE namespace.nspname = current_schema() AND relation.relname = 'exchanges' \
                     AND constraint_row.contype = 'u' \
                 GROUP BY constraint_row.oid",
            )
            .fetch_all(&pool)
            .await
            .expect("unique constraints");
            let columns = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
            assert!(unique.contains(&columns(&[
                "sender_wallet",
                "document_id",
                "document_version",
                "recipient_wallet"
            ])));
            assert!(!unique.contains(&columns(&[
                "document_id",
                "document_version",
                "recipient_wallet"
            ])));
        }

        #[tokio::test]
        async fn migrated_schema_has_no_placeholder_defaults() {
            let (_fixture, pool) = migrated().await;
            let listed = [
                ("exchanges", "schema_id"),
                ("exchanges", "schema_version"),
                ("exchanges", "envelope_version"),
                ("exchanges", "registry_sequence"),
                ("audit_events", "envelope_version"),
                ("audit_events", "protected_hash"),
                ("audit_events", "sender_wallet"),
                ("audit_events", "recipient_wallet"),
                ("audit_events", "document_id"),
                ("audit_events", "document_version"),
                ("audit_events", "registry_sequence"),
                ("audit_events", "signature"),
                ("exchanges", "committed_at"),
                ("audit_events", "committed_at"),
            ];
            for (table, column) in listed {
                let default: Option<Option<String>> = sqlx::query_scalar(
                    "SELECT column_default::text FROM information_schema.columns \
                     WHERE table_schema = current_schema() AND table_name = $1 \
                     AND column_name = $2",
                )
                .bind(table)
                .bind(column)
                .fetch_optional(&pool)
                .await
                .expect("column default");
                assert_eq!(default, Some(None), "{table}.{column}");
            }
            for table in ["exchanges", "audit_events"] {
                let nullable: String = sqlx::query_scalar(
                    "SELECT is_nullable::text FROM information_schema.columns \
                     WHERE table_schema = current_schema() AND table_name = $1 \
                     AND column_name = 'committed_at'",
                )
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("commit time column");
                assert_eq!(nullable, "NO", "{table}.committed_at");
            }
        }

        /// A schema migrated to version 4 only, as a server before the commit-time column left it.
        async fn at_version_four() -> (FixtureFiles, PgPool) {
            let (fixture, pool) = created().await;
            Migrator::new(EmbeddedMigrations)
                .await
                .expect("embedded migrations")
                .run_to(4, &pool)
                .await
                .expect("migrations 1 to 4");
            (fixture, pool)
        }

        #[tokio::test]
        async fn commit_time_migration_refuses_stored_rows() {
            let (_fixture, pool) = at_version_four().await;
            sqlx::raw_sql(
                "INSERT INTO exchanges (exchange_id, sender_wallet, recipient_wallet, document_id, \
                 document_version, request_nonce, idempotency_key, object_id, envelope_commitment, \
                 protected_hash, schema_id, schema_version, envelope_version, registry_sequence) \
                 VALUES ('exc_00000000000000000000000000000001', 'wal_0000000000000001', \
                 'wal_0000000000000002', 'doc_0000000000000001', 1, '\\x00', \
                 'idem_0000000000000001', 'obj_00000000000000000000000000000001', \
                 decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'), \
                 'urn:docchain:schema:service-application:1.0.0', '1.0.0', 1, 3); \
                 INSERT INTO audit_events (sequence, kind, exchange_id, object_id, commitment, \
                 previous_hash, event_hash, envelope_version, protected_hash, sender_wallet, \
                 recipient_wallet, document_id, document_version, registry_sequence, signature) \
                 SELECT 1, 'delivered', exchange_id, object_id, envelope_commitment, \
                 decode(repeat('00', 32), 'hex'), decode(repeat('33', 32), 'hex'), 1, \
                 protected_hash, sender_wallet, recipient_wallet, document_id, document_version, \
                 registry_sequence, decode(repeat('44', 64), 'hex') FROM exchanges",
            )
            .execute(&pool)
            .await
            .expect("rows stored at version 4");
            let rows = |pool: PgPool| async move {
                sqlx::query_as::<_, (String, i64)>(
                    "SELECT exchange_id, (SELECT COUNT(*) FROM audit_events) FROM exchanges",
                )
                .fetch_all(&pool)
                .await
                .expect("stored rows")
            };
            let before = rows(pool.clone()).await;
            assert_eq!(before.len(), 1);

            assert_eq!(migrate(&pool).await, Err(StoreError::Permanent));
            let versions: Vec<i64> =
                sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                    .fetch_all(&pool)
                    .await
                    .expect("recorded versions");
            assert_eq!(versions, [1, 2, 3, 4]);
            assert_eq!(rows(pool.clone()).await, before);
            let columns: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND column_name = 'committed_at'",
            )
            .fetch_one(&pool)
            .await
            .expect("commit time columns");
            assert_eq!(columns, 0);
            // SQLx keeps its database-wide migration lock on a failed run's connection, so this
            // pool closes before any other schema migrates.
            pool.close().await;

            // An empty schema at version 4 migrates.
            let (_empty, empty_pool) = at_version_four().await;
            assert_eq!(migrate(&empty_pool).await, Ok(()));
        }

        #[tokio::test]
        async fn commit_time_round_trips_unchanged() {
            use crate::providers::AuditKey;

            let (fixture, _owner) = migrated().await;
            let audit_key_path = fixture.root.join("audit.key");
            let integrity = AuditKey::load(&audit_key_path).expect("audit key");
            let store = PgExchangeStore::new(
                fixture.runtime_pool().await.expect("runtime pool"),
                fixture.schema.clone(),
            );
            // 1970-01-02T00:00:00Z: no clock read during this test can produce it.
            let committed_at = Timestamp::from_unix_seconds(86_400);
            let sender = WalletId::new("wal_0000000000000001").expect("wallet");
            let key = IdempotencyKey::new("idem_0000000000000001").expect("key");
            let record = ExchangeRecord {
                exchange_id: ExchangeId::new("exc_00000000000000000000000000000001")
                    .expect("exchange"),
                sender: sender.clone(),
                recipient: WalletId::new("wal_0000000000000002").expect("wallet"),
                document_id: DocumentId::new("doc_0000000000000001").expect("document"),
                document_version: DocumentVersion::new(1).expect("version"),
                request_nonce: RequestNonce::new([5; 16]),
                idempotency_key: key.clone(),
                schema_id: "urn:docchain:schema:service-application:1.0.0".to_owned(),
                schema_version: "1.0.0".to_owned(),
                object_id: ObjectId::new("obj_00000000000000000000000000000001").expect("object"),
                envelope_commitment: [1; 32],
                protected_hash: [2; 32],
                envelope_version: 1,
                registry_sequence: 3,
                committed_at,
                accepted: false,
            };
            let draft = |kind| EventDraft {
                kind,
                exchange_id: record.exchange_id.clone(),
                object_id: record.object_id.clone(),
                envelope_commitment: record.envelope_commitment,
                envelope_version: record.envelope_version,
                protected_hash: record.protected_hash,
                sender: record.sender.clone(),
                recipient: record.recipient.clone(),
                document_id: record.document_id.clone(),
                document_version: record.document_version,
                registry_sequence: record.registry_sequence,
                committed_at: record.committed_at,
            };
            store
                .commit_send(&record, draft(EventKind::Delivered), &integrity, 100)
                .await
                .expect("send");
            let credit = CreditPosting {
                eligibility_key: docchain_domain::acceptance_eligibility_key(&record.exchange_id),
                wallet: sender.clone(),
                amount: 1,
            };
            assert_eq!(
                store
                    .commit_acceptance(
                        &record.exchange_id,
                        &IdempotencyKey::new("idem_accept0000000001").expect("key"),
                        &credit,
                        draft(EventKind::Accepted),
                        &integrity,
                    )
                    .await,
                Ok(AcceptanceOutcome::Recorded)
            );

            let found = store
                .find(&record.exchange_id)
                .await
                .expect("find")
                .expect("stored exchange");
            assert_eq!(found.committed_at, committed_at);
            let by_key = store
                .find_by_idempotency(&sender, &key)
                .await
                .expect("find by idempotency key")
                .expect("stored exchange");
            assert_eq!(by_key.committed_at, committed_at);
            let events = store
                .page(AuditReadRequest {
                    snapshot: None,
                    after_sequence: 0,
                    limit: 10,
                })
                .await
                .expect("events")
                .events;
            assert_eq!(
                events
                    .iter()
                    .map(|event| (event.draft.kind, event.draft.committed_at))
                    .collect::<Vec<_>>(),
                [
                    (EventKind::Delivered, committed_at),
                    (EventKind::Accepted, committed_at)
                ]
            );
        }

        /// Runs one statement as the table owner, whose pool `pool` is, with the append-only
        /// triggers disabled.
        async fn tamper(pool: &PgPool, statement: &str) {
            let mut transaction = pool.begin().await.expect("transaction");
            for action in ["DISABLE", "ENABLE ALWAYS"] {
                for trigger in [
                    "audit_events_refuse_update_delete",
                    "audit_events_refuse_truncate",
                ] {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                        "ALTER TABLE audit_events {action} TRIGGER {trigger}"
                    )))
                    .execute(&mut *transaction)
                    .await
                    .expect("trigger");
                }
                if action == "DISABLE" {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
                        .execute(&mut *transaction)
                        .await
                        .expect("tamper");
                }
            }
            transaction.commit().await.expect("commit");
        }

        #[tokio::test]
        async fn audit_pages_are_contiguous_and_hold_the_manifest_snapshot_across_append() {
            use crate::providers::AuditKey;

            let (fixture, pool) = migrated().await;
            let integrity = AuditKey::load(&fixture.root.join("audit.key")).expect("audit key");
            let store = PgExchangeStore::new(
                fixture.runtime_pool().await.expect("runtime pool"),
                fixture.schema.clone(),
            );
            let send = |index: u8| {
                let record = ExchangeRecord {
                    exchange_id: ExchangeId::new(format!(
                        "exc_000000000000000000000000000000{index:02}"
                    ))
                    .expect("exchange"),
                    sender: WalletId::new("wal_0000000000000001").expect("wallet"),
                    recipient: WalletId::new("wal_0000000000000002").expect("wallet"),
                    document_id: DocumentId::new("doc_0000000000000001").expect("document"),
                    document_version: DocumentVersion::new(u64::from(index)).expect("version"),
                    request_nonce: RequestNonce::new([index; 16]),
                    idempotency_key: IdempotencyKey::new(format!("idem_00000000000000{index:02}"))
                        .expect("key"),
                    schema_id: "urn:docchain:schema:service-application:1.0.0".to_owned(),
                    schema_version: "1.0.0".to_owned(),
                    object_id: ObjectId::new(format!(
                        "obj_000000000000000000000000000000{index:02}"
                    ))
                    .expect("object"),
                    envelope_commitment: [index; 32],
                    protected_hash: [2; 32],
                    envelope_version: 1,
                    registry_sequence: 3,
                    committed_at: Timestamp::from_unix_seconds(86_400),
                    accepted: false,
                };
                let draft = EventDraft {
                    kind: EventKind::Delivered,
                    exchange_id: record.exchange_id.clone(),
                    object_id: record.object_id.clone(),
                    envelope_commitment: record.envelope_commitment,
                    envelope_version: record.envelope_version,
                    protected_hash: record.protected_hash,
                    sender: record.sender.clone(),
                    recipient: record.recipient.clone(),
                    document_id: record.document_id.clone(),
                    document_version: record.document_version,
                    registry_sequence: record.registry_sequence,
                    committed_at: record.committed_at,
                };
                (record, draft)
            };
            let read = |snapshot, after_sequence, limit| {
                store.page(AuditReadRequest {
                    snapshot,
                    after_sequence,
                    limit,
                })
            };

            let empty = read(None, 0, 1).await.expect("empty chain");
            assert_eq!(empty.snapshot, AuditSnapshot::new(0, None).expect("empty"));
            assert!(empty.events.is_empty() && !empty.has_more);

            for index in 1..=3 {
                let (record, draft) = send(index);
                store
                    .commit_send(&record, draft, &integrity, 100)
                    .await
                    .expect("send");
            }
            // The initial page selects the current tail and reads limit + 1 rows to know more.
            let first = read(None, 0, 1).await.expect("first page");
            let snapshot = first.snapshot;
            assert_eq!(snapshot.event_count(), 3);
            assert!(first.has_more);
            assert_eq!(first.events.len(), 1);
            assert_eq!(first.events[0].previous_hash, [0; 32]);
            let whole = read(None, 0, 3).await.expect("whole chain");
            assert!(!whole.has_more);
            assert_eq!(snapshot.head(), Some(whole.events[2].checkpoint()));

            // An append after selection is excluded from the manifest snapshot.
            let (record, draft) = send(4);
            store
                .commit_send(&record, draft, &integrity, 100)
                .await
                .expect("append after snapshot");
            let second = read(Some(snapshot), 1, 1).await.expect("second page");
            assert_eq!(second.snapshot, snapshot);
            assert_eq!(second.events[0].sequence, 2);
            assert_eq!(second.events[0].previous_hash, first.events[0].event_hash);
            assert!(second.has_more);
            let last = read(Some(snapshot), 2, 500).await.expect("last page");
            assert_eq!(
                last.events
                    .iter()
                    .map(|event| event.sequence)
                    .collect::<Vec<_>>(),
                [3]
            );
            assert!(!last.has_more);

            // A fresh selection is the current tail, never an older signed head.
            let fresh = read(None, 0, 1).await.expect("fresh selection");
            assert_eq!(fresh.snapshot.event_count(), 4);

            // A head that is not stored, or stored differently, is a changed snapshot.
            let mut altered = snapshot.head().expect("head");
            altered.event_hash[0] ^= 1;
            let mut missing = altered;
            missing.sequence = 9;
            for changed in [
                AuditSnapshot::new(3, Some(altered)).expect("altered"),
                AuditSnapshot::new(9, Some(missing)).expect("missing"),
                AuditSnapshot::new(0, None).expect("empty"),
            ] {
                assert_eq!(
                    read(Some(changed), 0, 1).await,
                    Err(AuditReadError::SnapshotChanged)
                );
            }
            assert_eq!(
                read(Some(snapshot), 4, 1).await,
                Err(AuditReadError::SnapshotChanged)
            );
            assert_eq!(read(None, 0, 0).await, Err(AuditReadError::Invariant));
            assert_eq!(read(None, 0, 501).await, Err(AuditReadError::Invariant));

            // A stored gap breaks the link to the cursor inside the snapshot read.
            tamper(&pool, "DELETE FROM audit_events WHERE sequence = 2").await;
            assert_eq!(
                read(Some(snapshot), 1, 1).await,
                Err(AuditReadError::SnapshotChanged)
            );
            assert_eq!(
                read(Some(snapshot), 0, 3)
                    .await
                    .map(|page| page.events.len()),
                Ok(2)
            );
        }

        #[tokio::test]
        async fn connection_uses_only_the_configured_schema() {
            let (fixture, _owner) = migrated().await;
            let service = DocchainService::compose(&fixture.settings)
                .await
                .expect("composed service");
            let (schema, application, search_path): (String, String, String) = sqlx::query_as(
                "SELECT current_schema()::text, current_setting('application_name'), \
                 current_setting('search_path')",
            )
            .fetch_one(service.pool())
            .await
            .expect("session settings");
            assert_eq!(
                (schema.as_str(), application.as_str(), search_path.as_str()),
                (
                    fixture.schema.as_str(),
                    "docchain-server",
                    fixture.schema.as_str()
                )
            );
            let public_tables: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = $1 AND table_name = '_sqlx_migrations'",
            )
            .bind(&fixture.schema)
            .fetch_one(service.pool())
            .await
            .expect("migration table");
            assert_eq!(public_tables, 1);
        }

        #[tokio::test]
        async fn missing_schema_fails_startup() {
            let fixture = FixtureFiles::write().expect("fixture files");
            let composed = DocchainService::compose(&fixture.settings).await;
            assert!(matches!(
                composed,
                Err(ServiceError::Initialization("database schema"))
            ));
            // It failed before migrations: nothing created the schema or any table.
            assert_eq!(fixture.schema_exists().await.ok(), Some(false));
        }

        /// The runtime privilege violations of `role`, checked on one connection of `pool`.
        async fn violations(pool: &PgPool, role: &str) -> BTreeSet<PrivilegeViolation> {
            let mut conn = pool.acquire().await.expect("connection");
            runtime_privilege_violations(&mut conn, role)
                .await
                .expect("privilege check")
        }

        /// The name of the role with OID 10, the cluster's bootstrap superuser.
        async fn bootstrap_role(pool: &PgPool) -> String {
            sqlx::query_scalar("SELECT rolname::text FROM pg_roles WHERE oid = 10")
                .fetch_one(pool)
                .await
                .expect("bootstrap role")
        }

        #[tokio::test]
        async fn runtime_privilege_rule_accepts_only_the_matrix() {
            use PrivilegeViolation as V;

            let (fixture, owner) = migrated().await;
            let runtime_role = fixture.settings.database.user.clone();
            let owner_role = fixture.owner.owner.clone();
            assert_eq!(violations(&owner, &runtime_role).await, BTreeSet::new());
            assert!(
                violations(&owner, "pg_monitor")
                    .await
                    .contains(&V::Membership)
            );
            let bootstrap = bootstrap_role(&owner).await;
            assert!(violations(&owner, &bootstrap).await.contains(&V::Attribute));
            assert!(
                violations(&owner, "docchain_no_such_role")
                    .await
                    .contains(&V::Attribute)
            );
            let of_owner = violations(&owner, &owner_role).await;
            assert!(of_owner.contains(&V::ObjectOwner), "{of_owner:?}");
            assert!(of_owner.contains(&V::SchemaPrivilege), "{of_owner:?}");

            // One grant beyond the matrix at a time, each revoked afterwards.
            let grant =
                |statement: &str| sqlx::AssertSqlSafe(statement.replace("RUNTIME", &runtime_role));
            for (granted, revoked, expected) in [
                (
                    "GRANT EXECUTE ON FUNCTION refuse_append_only_mutation() TO RUNTIME",
                    "REVOKE EXECUTE ON FUNCTION refuse_append_only_mutation() FROM RUNTIME",
                    V::FunctionPrivilege,
                ),
                (
                    "GRANT USAGE ON SEQUENCE audit_events_sequence_seq TO RUNTIME",
                    "REVOKE USAGE ON SEQUENCE audit_events_sequence_seq FROM RUNTIME",
                    V::SequencePrivilege,
                ),
                (
                    "GRANT SELECT ON audit_events TO RUNTIME WITH GRANT OPTION",
                    "REVOKE GRANT OPTION FOR SELECT ON audit_events FROM RUNTIME",
                    V::GrantOption,
                ),
                (
                    "GRANT DELETE ON audit_events TO RUNTIME",
                    "REVOKE DELETE ON audit_events FROM RUNTIME",
                    V::TablePrivilege,
                ),
                (
                    "GRANT UPDATE (sender_wallet) ON exchanges TO RUNTIME",
                    "REVOKE UPDATE (sender_wallet) ON exchanges FROM RUNTIME",
                    V::ColumnPrivilege,
                ),
                (
                    "GRANT CREATE ON SCHEMA SCHEMA_NAME TO RUNTIME",
                    "REVOKE CREATE ON SCHEMA SCHEMA_NAME FROM RUNTIME",
                    V::SchemaPrivilege,
                ),
            ] {
                let granted = granted.replace("SCHEMA_NAME", &fixture.schema);
                let revoked = revoked.replace("SCHEMA_NAME", &fixture.schema);
                sqlx::raw_sql(grant(&granted))
                    .execute(&owner)
                    .await
                    .expect("grant");
                let found = violations(&owner, &runtime_role).await;
                assert!(found.contains(&expected), "{granted}: {found:?}");
                sqlx::raw_sql(grant(&revoked))
                    .execute(&owner)
                    .await
                    .expect("revoke");
                assert_eq!(
                    violations(&owner, &runtime_role).await,
                    BTreeSet::new(),
                    "{revoked}"
                );
            }

            // A new owner table with no grant leaves the rule intact; a grant on it does not.
            sqlx::raw_sql("CREATE TABLE unlisted (id BIGINT)")
                .execute(&owner)
                .await
                .expect("new table");
            assert_eq!(violations(&owner, &runtime_role).await, BTreeSet::new());
            sqlx::raw_sql(grant("GRANT SELECT ON unlisted TO RUNTIME"))
                .execute(&owner)
                .await
                .expect("grant on new table");
            assert!(
                violations(&owner, &runtime_role)
                    .await
                    .contains(&V::TablePrivilege)
            );
            // A listed relation that is missing is a mismatch too.
            sqlx::raw_sql("DROP TABLE unlisted; ALTER TABLE acceptances RENAME TO renamed")
                .execute(&owner)
                .await
                .expect("rename a listed table");
            assert!(
                violations(&owner, &runtime_role)
                    .await
                    .contains(&V::TablePrivilege)
            );
        }

        #[tokio::test]
        async fn runtime_state_left_uncommitted_breaks_the_rule_on_its_own_connection() {
            let (fixture, _owner) = migrated().await;
            let runtime = fixture.runtime_pool().await.expect("runtime pool");
            let role = fixture.settings.database.user.clone();
            for (statement, expected) in [
                (
                    "ALTER ROLE CURRENT_USER SET statement_timeout = '1min'",
                    PrivilegeViolation::RoleSetting,
                ),
                ("SELECT lo_create(0)", PrivilegeViolation::ObjectOwner),
            ] {
                // Never committed on any path: dropping the transaction also rolls it back.
                let mut transaction = runtime.begin().await.expect("transaction");
                sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
                    .execute(&mut *transaction)
                    .await
                    .expect("runtime statement");
                let found = runtime_privilege_violations(&mut transaction, &role)
                    .await
                    .expect("privilege check");
                assert!(found.contains(&expected), "{statement}: {found:?}");
                transaction.rollback().await.expect("rollback");
                assert_eq!(violations(&runtime, &role).await, BTreeSet::new());
            }
        }

        #[tokio::test]
        async fn superuser_check_treats_unknown_roles_as_superusers() {
            let (fixture, owner) = created().await;
            let mut conn = owner.acquire().await.expect("connection");
            let bootstrap = bootstrap_role(&owner).await;
            for (role, expected) in [
                (fixture.owner.owner.as_str(), false),
                (fixture.settings.database.user.as_str(), false),
                (bootstrap.as_str(), true),
                ("docchain_no_such_role", true),
            ] {
                assert_eq!(
                    role_is_superuser(&mut conn, role).await,
                    Ok(expected),
                    "{role}"
                );
            }
            assert!(!session_is_superuser(&mut conn).await);
        }

        /// Owner connection options that set `docchain.runtime_role` to `runtime`, or not at
        /// all.
        fn owner_options_with(
            fixture: &FixtureFiles,
            runtime: Option<&str>,
        ) -> sqlx::postgres::PgConnectOptions {
            let owner = &fixture.owner;
            let options = sqlx::postgres::PgConnectOptions::new_without_pgpass()
                .host(&owner.host)
                .port(owner.port)
                .username(&owner.owner)
                .password(owner.owner_password.expose())
                .database(&owner.name)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable)
                .options([("search_path", fixture.schema.as_str())]);
            match runtime {
                Some(runtime) => options.options([("docchain.runtime_role", runtime)]),
                None => options,
            }
        }

        #[tokio::test]
        async fn grant_migration_refuses_an_unacceptable_runtime_role() {
            let (probe, probe_owner) = created().await;
            let bootstrap = bootstrap_role(&probe_owner).await;
            let owner_role = probe.owner.owner.clone();
            drop(probe_owner);
            drop(probe);
            for runtime in [
                None,
                Some(""),
                Some("docchain_no_such_role"),
                Some(owner_role.as_str()),
                Some("pg_monitor"),
                Some(bootstrap.as_str()),
            ] {
                let (fixture, owner) = created().await;
                Migrator::new(EmbeddedMigrations)
                    .await
                    .expect("embedded migrations")
                    .run_to(5, &owner)
                    .await
                    .expect("migrations 1 to 5");
                let refused = crate::harness::guarded_pool(
                    owner_options_with(&fixture, runtime),
                    "owner refused",
                )
                .await
                .expect("owner pool");
                assert_eq!(
                    migrate(&refused).await,
                    Err(StoreError::Permanent),
                    "{runtime:?}"
                );
                refused.close().await;
                let versions: Vec<i64> =
                    sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                        .fetch_all(&owner)
                        .await
                        .expect("recorded versions");
                assert_eq!(versions, [1, 2, 3, 4, 5], "{runtime:?}");
                if let Some(runtime) = runtime.filter(|name| !name.is_empty()) {
                    let granted: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM pg_namespace AS namespace, \
                         aclexplode(namespace.nspacl) AS entry \
                         JOIN pg_roles AS role ON role.oid = entry.grantee \
                         WHERE namespace.nspname = $1 AND role.rolname = $2)",
                    )
                    .bind(&fixture.schema)
                    .bind(runtime)
                    .fetch_one(&owner)
                    .await
                    .expect("schema grants");
                    let acceptable = runtime == owner_role;
                    assert!(!granted || acceptable, "{runtime}");
                }
            }
        }

        #[tokio::test]
        async fn grant_migration_pins_triggers_and_search_paths() {
            let (fixture, owner) = migrated().await;
            let triggers: Vec<(String, String)> = sqlx::query_as(
                "SELECT trigger_row.tgname::text, trigger_row.tgenabled::text \
                 FROM pg_trigger AS trigger_row \
                 JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid \
                 WHERE relation.relnamespace = current_schema()::regnamespace \
                     AND NOT trigger_row.tgisinternal ORDER BY 1",
            )
            .fetch_all(&owner)
            .await
            .expect("triggers");
            assert_eq!(triggers.len(), 11, "{triggers:?}");
            assert!(
                triggers.iter().all(|(_, enabled)| enabled == "A"),
                "{triggers:?}"
            );
            let functions: Vec<(String, Option<Vec<String>>)> = sqlx::query_as(
                "SELECT proname::text, proconfig FROM pg_proc \
                 WHERE pronamespace = current_schema()::regnamespace ORDER BY 1",
            )
            .fetch_all(&owner)
            .await
            .expect("functions");
            let pinned = Some(vec![format!("search_path={}, pg_temp", fixture.schema)]);
            assert_eq!(
                functions,
                [
                    ("credit_transaction_is_balanced".to_owned(), pinned.clone()),
                    ("refuse_acceptance_reset".to_owned(), pinned.clone()),
                    ("refuse_append_only_mutation".to_owned(), pinned),
                ]
            );
        }

        /// An invented exchange from wallet 1 to wallet 2, distinct for each `index`.
        fn exchange_record(index: u8) -> ExchangeRecord {
            ExchangeRecord {
                exchange_id: ExchangeId::new(format!(
                    "exc_000000000000000000000000000000{index:02}"
                ))
                .expect("exchange"),
                sender: WalletId::new("wal_0000000000000001").expect("wallet"),
                recipient: WalletId::new("wal_0000000000000002").expect("wallet"),
                document_id: DocumentId::new("doc_0000000000000001").expect("document"),
                document_version: DocumentVersion::new(u64::from(index)).expect("version"),
                request_nonce: RequestNonce::new([index; 16]),
                idempotency_key: IdempotencyKey::new(format!("idem_00000000000000{index:02}"))
                    .expect("key"),
                schema_id: "urn:docchain:schema:service-application:1.0.0".to_owned(),
                schema_version: "1.0.0".to_owned(),
                object_id: ObjectId::new(format!("obj_000000000000000000000000000000{index:02}"))
                    .expect("object"),
                envelope_commitment: [index; 32],
                protected_hash: [2; 32],
                envelope_version: 1,
                registry_sequence: 3,
                committed_at: Timestamp::from_unix_seconds(86_400),
                accepted: false,
            }
        }

        /// The event `record` produces as `kind`.
        fn event_draft(record: &ExchangeRecord, kind: EventKind) -> EventDraft {
            EventDraft {
                kind,
                exchange_id: record.exchange_id.clone(),
                object_id: record.object_id.clone(),
                envelope_commitment: record.envelope_commitment,
                envelope_version: record.envelope_version,
                protected_hash: record.protected_hash,
                sender: record.sender.clone(),
                recipient: record.recipient.clone(),
                document_id: record.document_id.clone(),
                document_version: record.document_version,
                registry_sequence: record.registry_sequence,
                committed_at: record.committed_at,
            }
        }

        #[tokio::test]
        async fn credit_snapshot_groups_the_ledger_within_its_bound() {
            use crate::providers::AuditKey;

            let (fixture, owner) = migrated().await;
            let integrity = AuditKey::load(&fixture.root.join("audit.key")).expect("audit key");
            let store = PgExchangeStore::new(
                fixture.runtime_pool().await.expect("runtime pool"),
                fixture.schema.clone(),
            );
            let record = exchange_record;
            let draft = event_draft;
            let accept = |record: ExchangeRecord, key: &'static str| {
                let store = &store;
                let integrity = &integrity;
                async move {
                    store
                        .commit_acceptance(
                            &record.exchange_id,
                            &IdempotencyKey::new(key).expect("key"),
                            &CreditPosting {
                                eligibility_key: docchain_domain::acceptance_eligibility_key(
                                    &record.exchange_id,
                                ),
                                wallet: record.sender.clone(),
                                amount: 1,
                            },
                            draft(&record, EventKind::Accepted),
                            integrity,
                        )
                        .await
                        .expect("acceptance")
                }
            };

            let empty = store.credit_snapshot(10).await.expect("empty ledger");
            assert_eq!(empty.snapshot.event_count(), 0);
            assert!(empty.transactions.is_empty());
            for index in 1..=2 {
                store
                    .commit_send(
                        &record(index),
                        draft(&record(index), EventKind::Delivered),
                        &integrity,
                        100,
                    )
                    .await
                    .expect("send");
            }
            accept(record(1), "idem_accept0000000001").await;

            let read = store.credit_snapshot(10).await.expect("ledger");
            assert_eq!(read.snapshot.event_count(), 3);
            assert_eq!(
                read.transactions,
                [CreditLedgerTransaction {
                    eligibility_key: format!("acceptance:{}", record(1).exchange_id),
                    exchange_id: Some(record(1).exchange_id.to_string()),
                    entries: vec![
                        CreditLedgerEntry {
                            account: "issuance".to_owned(),
                            amount: -1,
                        },
                        CreditLedgerEntry {
                            account: "wal_0000000000000001".to_owned(),
                            amount: 1,
                        },
                    ],
                }]
            );
            assert_eq!(
                store.credit_snapshot(0).await.map(|_| ()),
                Err(AuditReadError::Exhausted)
            );

            // A later snapshot includes a later acceptance in both its tail and its ledger.
            accept(record(2), "idem_accept0000000002").await;
            let later = store.credit_snapshot(10).await.expect("later ledger");
            assert_eq!(
                (later.snapshot.event_count(), later.transactions.len()),
                (4, 2)
            );

            // Entries without a transaction, and a transaction without entries, as the owner
            // could store them, are returned as they are.
            sqlx::raw_sql(
                "ALTER TABLE credit_entries DROP CONSTRAINT credit_entries_eligibility_key_fkey; \
                 ALTER TABLE credit_transactions DISABLE TRIGGER credit_transactions_balanced; \
                 ALTER TABLE credit_transactions DROP CONSTRAINT credit_transactions_exchange_id_key; \
                 INSERT INTO credit_entries VALUES ('orphan', 'wal_0000000000000003', 1); \
                 INSERT INTO credit_transactions \
                 SELECT 'lonely', exchange_id FROM credit_transactions LIMIT 1",
            )
            .execute(&owner)
            .await
            .expect("owner tampering");
            let tampered = store.credit_snapshot(10).await.expect("tampered ledger");
            let shapes = tampered
                .transactions
                .iter()
                .map(|transaction| {
                    (
                        transaction.eligibility_key.as_str(),
                        transaction.exchange_id.is_some(),
                        transaction.entries.len(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                shapes,
                [
                    (
                        format!("acceptance:{}", record(1).exchange_id).as_str(),
                        true,
                        2
                    ),
                    (
                        format!("acceptance:{}", record(2).exchange_id).as_str(),
                        true,
                        2
                    ),
                    ("lonely", true, 0),
                    ("orphan", false, 1),
                ]
            );
            assert_eq!(
                store.credit_snapshot(2).await.map(|_| ()),
                Err(AuditReadError::Exhausted)
            );
        }

        #[tokio::test]
        async fn credit_snapshot_excludes_a_credit_committed_while_it_waits() {
            use crate::providers::AuditKey;

            let (fixture, owner) = migrated().await;
            let integrity = AuditKey::load(&fixture.root.join("audit.key")).expect("audit key");
            let store = PgExchangeStore::new(
                fixture.runtime_pool().await.expect("runtime pool"),
                fixture.schema.clone(),
            );
            let sent = exchange_record(1);
            store
                .commit_send(
                    &sent,
                    event_draft(&sent, EventKind::Delivered),
                    &integrity,
                    100,
                )
                .await
                .expect("send");
            let before = store.credit_snapshot(10).await.expect("ledger before");
            assert_eq!(before.snapshot.event_count(), 1);
            assert!(before.transactions.is_empty());

            // Taken out of the pool, so any failure closes the session and releases the lock.
            let mut holder = owner.acquire().await.expect("holder").detach();
            sqlx::raw_sql("BEGIN; LOCK TABLE credit_entries IN ACCESS EXCLUSIVE MODE")
                .execute(&mut holder)
                .await
                .expect("lock the ledger entries");

            // The read takes its snapshot with the tail, then waits for the entries lock.
            let read = store.credit_snapshot(10);
            tokio::pin!(read);
            let entries = format!("{}.credit_entries", fixture.schema);
            tokio::select! {
                biased;
                returned = &mut read => {
                    panic!("the read returned while the entries were locked: {returned:?}")
                }
                _waiter = crate::harness::access_share_waiter(&owner, &entries) => {}
            }

            let key = docchain_domain::acceptance_eligibility_key(&sent.exchange_id);
            sqlx::query(
                "INSERT INTO credit_transactions (eligibility_key, exchange_id) VALUES ($1, $2)",
            )
            .bind(&key)
            .bind(sent.exchange_id.to_string())
            .execute(&mut holder)
            .await
            .expect("credit transaction");
            sqlx::query(
                "INSERT INTO credit_entries (eligibility_key, account_id, amount) \
                 VALUES ($1, 'issuance', -1), ($1, $2, 1)",
            )
            .bind(&key)
            .bind(sent.sender.to_string())
            .execute(&mut holder)
            .await
            .expect("credit entries");
            sqlx::raw_sql("COMMIT")
                .execute(&mut holder)
                .await
                .expect("commit the credit and release the lock");

            let read = tokio::time::timeout(Duration::from_secs(10), read)
                .await
                .expect("the read returns within 10 s of the release")
                .expect("ledger read while waiting");
            assert!(read.snapshot == before.snapshot, "the tail moved");
            assert_eq!(read.transactions, before.transactions);

            // A later snapshot holds that credit, so its absence above is not vacuous.
            let later = store.credit_snapshot(10).await.expect("ledger after");
            assert!(later.snapshot == before.snapshot, "the tail moved");
            assert_eq!(
                later.transactions,
                [CreditLedgerTransaction {
                    eligibility_key: key,
                    exchange_id: Some(sent.exchange_id.to_string()),
                    entries: vec![
                        CreditLedgerEntry {
                            account: "issuance".to_owned(),
                            amount: -1,
                        },
                        CreditLedgerEntry {
                            account: sent.sender.to_string(),
                            amount: 1,
                        },
                    ],
                }]
            );
        }
    }
}
