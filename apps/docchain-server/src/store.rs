//! PostgreSQL exchange/event adapter and filesystem ciphertext adapter.

use std::{
    borrow::Cow,
    future::Future,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, Instant},
};

use docchain_application::{
    AcceptanceOutcome, CreditPosting, DocumentStore, EventIntegrity, ExchangeRecord, ExchangeStore,
    StoreError,
};
use docchain_domain::{
    AuditEvent, DocumentId, DocumentVersion, EventDraft, EventKind, ExchangeId, IdempotencyKey,
    ObjectId, RequestNonce, Timestamp, WalletId, event_signature_input,
};
use sqlx::{
    PgPool, Postgres, Row as _, SqlStr, Transaction,
    error::BoxDynError,
    migrate::{Migration, MigrationSource, MigrationType, Migrator},
};
use tokio::{fs, io::AsyncWriteExt as _, sync::Mutex, task::JoinHandle};

/// The forward-only migrations, embedded so the binary does not depend on the source tree.
///
/// Every file in `migrations/` must appear here, in version order; a unit test compares this list
/// with the directory.
const MIGRATIONS: [(i64, &str, &str); 5] = [
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

/// Applies every pending migration in order, each in its own transaction.
///
/// Each applied version is recorded with its checksum; a changed applied migration is refused.
///
/// # Errors
///
/// [`StoreError::Permanent`] when a migration fails or an applied one was changed.
pub(crate) async fn migrate(pool: &PgPool) -> Result<(), StoreError> {
    Migrator::new(EmbeddedMigrations)
        .await
        .map_err(|_| StoreError::Permanent)?
        .run(pool)
        .await
        .map_err(|_| StoreError::Permanent)
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
        Ok(Self {
            root,
            probe: Mutex::new(ProbeState::default()),
            probe_ttl,
            probe_timeout,
            hooks,
        })
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
}

impl PgExchangeStore {
    pub(crate) const fn new(pool: PgPool) -> Self {
        Self { pool }
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
             VALUES ($1, 'issuance', -1), ($1, $2, 1)",
        )
        .bind(&credit.eligibility_key)
        .bind(credit.wallet.as_str())
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

    async fn events(&self, limit: u32) -> Result<Vec<AuditEvent>, StoreError> {
        sqlx::query(
            "SELECT sequence, kind, exchange_id, object_id, commitment, envelope_version, \
             protected_hash, sender_wallet, recipient_wallet, document_id, document_version, \
             registry_sequence, committed_at, previous_hash, event_hash, signature \
             FROM audit_events ORDER BY sequence LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sql)?
        .into_iter()
        .map(row_to_event)
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
            [1, 2, 3, 4, 5]
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

        async fn migrated() -> (FixtureFiles, PgPool) {
            let fixture = FixtureFiles::write().expect("fixture files");
            fixture.create_schema().await.expect("schema");
            let pool = fixture.pool().await.expect("pool");
            migrate(&pool).await.expect("migrations");
            (fixture, pool)
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
            let fixture = FixtureFiles::write().expect("fixture files");
            fixture.create_schema().await.expect("schema");
            let pool = fixture.pool().await.expect("pool");
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

            let (fixture, pool) = migrated().await;
            let audit_key_path = fixture.root.join("audit.key");
            let integrity = AuditKey::load(&audit_key_path).expect("audit key");
            let store = PgExchangeStore::new(pool);
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
                eligibility_key: format!("acceptance:{}", record.exchange_id),
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
            let events = store.events(10).await.expect("events");
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

        #[tokio::test]
        async fn connection_uses_only_the_configured_schema() {
            let fixture = FixtureFiles::write().expect("fixture files");
            fixture.create_schema().await.expect("schema");
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
    }
}
