//! Composition of application use cases with the local adapters.

#[cfg(feature = "test-support")]
use std::sync::Arc;

use docchain_application::{
    AcceptanceResult, Actor, Adapters, Application, ApplicationError, AuditExportPage,
    AuditExportRequest, AuditKeyPin, AuditPublicKey, AuditReport, AuditSettings, Credential,
    Delivery, EventIntegrity as _, Limits, OperationalReadGrant, SendCopyCommand, StoreSweep,
    SweepError, sweep_debris,
};
#[cfg(feature = "test-support")]
use docchain_application::{AuditEventStore as _, AuditReadRequest};
#[cfg(feature = "test-support")]
use docchain_domain::sha256;
use docchain_domain::{Checkpoint, ExchangeId, IdempotencyKey, WalletId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use thiserror::Error;

#[cfg(feature = "test-support")]
use crate::config::MigrationSettings;
#[cfg(feature = "test-support")]
use crate::store::{PauseGate, ScanFault};
use crate::{
    config::{DatabaseSettings, Settings},
    crypto::CryptoEngine,
    providers::{
        AuditKey, FileIdentity, FileKeyRegistry, StaticSchemaRegistry, SystemClock, load_key_files,
    },
    store::{
        FileDocumentStore, LeaseError, LeaseHooks, MigrationState, PgExchangeStore, StoreLease,
        SweepBounds, migration_state, runtime_privilege_violations, schema_exists, session_roles,
    },
};

/// How one start runs its lease and sweep. Production uses the default: every bound at its
/// named constant, and no test hook.
#[derive(Clone, Debug, Default)]
pub struct StartOptions {
    /// Lease, drain, and sweep bounds.
    pub bounds: SweepBounds,
    /// Reached once the writer drain has recorded at least one transaction.
    #[cfg(feature = "test-support")]
    pub drain_recorded: Option<PauseGate>,
    /// A failure injected into the reference read.
    #[cfg(feature = "test-support")]
    pub scan_fault: Option<ScanFault>,
    /// Pauses each send after its object is written.
    #[cfg(feature = "test-support")]
    pub after_put_new: Option<PauseGate>,
    /// Pauses each send inside its transaction, before `COMMIT`.
    #[cfg(feature = "test-support")]
    pub before_send_commit: Option<PauseGate>,
}

/// Concrete statically-dispatched local adapters.
pub struct ServerAdapters {
    identity: FileIdentity,
    schemas: StaticSchemaRegistry,
    keys: FileKeyRegistry,
    crypto: CryptoEngine,
    integrity: AuditKey,
    documents: FileDocumentStore,
    exchanges: PgExchangeStore,
    clock: SystemClock,
}

impl Adapters for ServerAdapters {
    type Identity = FileIdentity;
    type Schemas = StaticSchemaRegistry;
    type Keys = FileKeyRegistry;
    type Crypto = CryptoEngine;
    type Integrity = AuditKey;
    type Documents = FileDocumentStore;
    type Exchanges = PgExchangeStore;
    type AuditEvents = PgExchangeStore;
    type Clock = SystemClock;

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }
    fn schemas(&self) -> &Self::Schemas {
        &self.schemas
    }
    fn keys(&self) -> &Self::Keys {
        &self.keys
    }
    fn crypto(&self) -> &Self::Crypto {
        &self.crypto
    }
    fn integrity(&self) -> &Self::Integrity {
        &self.integrity
    }
    fn documents(&self) -> &Self::Documents {
        &self.documents
    }
    fn exchanges(&self) -> &Self::Exchanges {
        &self.exchanges
    }
    fn audit_events(&self) -> &Self::AuditEvents {
        &self.exchanges
    }
    fn clock(&self) -> &Self::Clock {
        &self.clock
    }
}

/// Failures while composing or invoking the service.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// Stable application failure.
    #[error("request rejected")]
    Application(#[from] ApplicationError),
    /// Configuration or adapter initialization failed at the named step. The step names no
    /// path, credential, or key.
    #[error("service initialization failed: {0}")]
    Initialization(&'static str),
    /// A test-support inspection failed.
    #[cfg(feature = "test-support")]
    #[error("test inspection failed")]
    Inspection,
}

impl ServiceError {
    /// Stable response category with no document or secret content.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Application(error) => match error {
                ApplicationError::Unauthenticated => "unauthenticated",
                ApplicationError::Forbidden => "forbidden",
                ApplicationError::InvalidRequest => "invalid-request",
                ApplicationError::InvalidDocument => "invalid-document",
                ApplicationError::UnsupportedSchema => "unsupported-schema",
                ApplicationError::KeyBinding => "key-binding",
                ApplicationError::Replay => "replay",
                ApplicationError::PendingLimit => "pending-limit",
                ApplicationError::InvalidEnvelope => "invalid-envelope",
                ApplicationError::IntegrityFailure | ApplicationError::AuditMismatch(_) => {
                    "integrity-failure"
                }
                ApplicationError::AuditIncomplete => "audit-incomplete",
                ApplicationError::Unavailable | ApplicationError::Invariant => "dependency-failure",
            },
            Self::Initialization(_) => "dependency-failure",
            #[cfg(feature = "test-support")]
            Self::Inspection => "dependency-failure",
        }
    }
}

/// Connection options that ignore every `PG*` environment variable and password file: each
/// parameter is set here, and the configured schema is the connection's only `search_path`.
pub(crate) fn connect_options(database: &DatabaseSettings) -> PgConnectOptions {
    PgConnectOptions::new_without_pgpass()
        .host(&database.host)
        .port(database.port)
        .username(&database.user)
        .password(database.password.expose())
        .database(&database.name)
        .ssl_mode(PgSslMode::Disable)
        .application_name("docchain-server")
        .options([("search_path", database.schema.as_str())])
}

/// Connection options for the migration owner: the configured schema is the only
/// `search_path`, and `docchain.runtime_role` names the role migrations grant to.
pub(crate) fn migration_connect_options(
    settings: &crate::config::MigrationSettings,
) -> PgConnectOptions {
    PgConnectOptions::new_without_pgpass()
        .host(&settings.host)
        .port(settings.port)
        .username(&settings.owner)
        .password(settings.owner_password.expose())
        .database(&settings.name)
        .ssl_mode(PgSslMode::Disable)
        .application_name("docchain-migrate")
        .options([
            ("search_path", settings.schema.as_str()),
            ("docchain.runtime_role", settings.runtime_role.as_str()),
        ])
}

/// Fully composed local service. HTTP and test adapters call these use cases.
pub struct DocchainService {
    application: Application<ServerAdapters>,
    /// Held until the service drops, which releases both locks.
    #[cfg_attr(
        not(feature = "test-support"),
        expect(
            dead_code,
            reason = "held only so that dropping the service releases it"
        )
    )]
    lease: std::sync::Mutex<Option<StoreLease>>,
    sweep: StoreSweep,
    #[cfg(feature = "test-support")]
    sweep_elapsed: std::time::Duration,
}

impl DocchainService {
    /// Checks the configured database schema and role, then wires every adapter.
    ///
    /// It never applies migrations. Before any adapter is built, and so before anything can
    /// listen, it checks in order: that the schema exists, that every embedded migration is
    /// applied unchanged, that the connection's schema is the configured one, and that the
    /// connected role is its own session role and satisfies the runtime privilege rule.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Initialization`] naming the first failed step, never a user, password,
    /// path, SQL error, or which part of the privilege rule failed.
    pub async fn compose(settings: &Settings) -> Result<Self, ServiceError> {
        Self::compose_with(settings, Limits::default(), StartOptions::default()).await
    }

    /// The startup sweep's outcome, which `Display`s as the one report line: counts or a skip
    /// reason, never an object ID, path, or database identifier.
    #[must_use]
    pub const fn sweep_report(&self) -> StoreSweep {
        self.sweep
    }

    /// Time spent in this service's startup sweep.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn sweep_elapsed(&self) -> std::time::Duration {
        self.sweep_elapsed
    }

    pub(crate) async fn compose_with(
        settings: &Settings,
        limits: Limits,
        start: StartOptions,
    ) -> Result<Self, ServiceError> {
        let database = &settings.database;
        let options = connect_options(database);
        let pool = PgPoolOptions::new()
            .max_connections(database.max_connections)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options.clone())
            .await
            .map_err(|_| ServiceError::Initialization("database connection"))?;
        check_database(&pool, database.schema.as_str()).await?;

        let signing = load_key_files(&settings.keys.wallet_signing_private)
            .map_err(|_| ServiceError::Initialization("wallet signing key files"))?;
        let encryption = load_key_files(&settings.keys.wallet_encryption_private)
            .map_err(|_| ServiceError::Initialization("wallet encryption key files"))?;
        let integrity = AuditKey::load(&settings.keys.audit_private)
            .map_err(|_| ServiceError::Initialization("audit key file"))?;
        let public_key = integrity
            .public_key()
            .map_err(|_| ServiceError::Initialization("audit public key"))?;
        let public_proof = AuditPublicKey::new(
            public_key,
            AuditKeyPin::new(settings.keys.audit_public_key_fingerprint),
        )
        .map_err(|_| ServiceError::Initialization("audit public key fingerprint"))?;
        let audit = AuditSettings::new(
            public_proof,
            settings.audit.max_export_events,
            settings.audit.default_page_size,
        )
        .map_err(|_| ServiceError::Initialization("audit settings"))?;
        let identity = FileIdentity::load(&settings.identity_credentials_file)
            .map_err(|_| ServiceError::Initialization("identity credentials file"))?;
        let keys = FileKeyRegistry::load(&settings.keys)
            .map_err(|_| ServiceError::Initialization("key-binding registry"))?;
        let crypto = CryptoEngine::new(signing, encryption)
            .map_err(|_| ServiceError::Initialization("wallet key material"))?;
        let bounds = start.bounds;
        let documents = FileDocumentStore::new(settings.document_store_root.clone())
            .await
            .map_err(|_| ServiceError::Initialization("document store root"))?
            .with_bounds(bounds);
        let exchanges =
            PgExchangeStore::new(pool, database.schema.as_str().to_owned()).with_bounds(bounds);
        #[cfg(feature = "test-support")]
        let (documents, exchanges) = {
            let documents = match start.after_put_new.clone() {
                Some(gate) => documents.with_put_new_gate(gate),
                None => documents,
            };
            let exchanges = match start.before_send_commit.clone() {
                Some(gate) => exchanges.with_commit_gate(gate),
                None => exchanges,
            };
            (documents, exchanges.with_scan_fault(start.scan_fault))
        };
        let hooks = LeaseHooks {
            #[cfg(feature = "test-support")]
            drain_recorded: start.drain_recorded.clone(),
        };
        let (mut lease, permit) = StoreLease::acquire(
            &options,
            database.schema.as_str(),
            &documents,
            &bounds,
            &hooks,
        )
        .await
        .map_err(|error| {
            ServiceError::Initialization(match error {
                LeaseError::Exclusivity => "document store exclusivity",
                LeaseError::Binding => "document store binding",
            })
        })?;
        #[cfg(feature = "test-support")]
        let sweep_started = std::time::Instant::now();
        let sweep = match sweep_debris(permit, &documents, &exchanges).await {
            Ok(sweep) => sweep,
            Err(error) => {
                lease.release().await;
                return Err(ServiceError::Initialization(match error {
                    SweepError::Inventory => "document store inventory",
                    SweepError::References => "document store references",
                    SweepError::Removal => "document store sweep",
                }));
            }
        };
        #[cfg(feature = "test-support")]
        let sweep_elapsed = sweep_started.elapsed();
        if lease.downgrade(&bounds).await.is_err() {
            lease.release().await;
            return Err(ServiceError::Initialization("document store exclusivity"));
        }
        let adapters = ServerAdapters {
            identity,
            schemas: StaticSchemaRegistry,
            keys,
            crypto,
            integrity,
            documents,
            exchanges,
            clock: SystemClock,
        };
        Ok(Self {
            application: Application::new(adapters, limits, audit),
            lease: std::sync::Mutex::new(Some(lease)),
            sweep,
            #[cfg(feature = "test-support")]
            sweep_elapsed,
        })
    }

    /// Authenticates one presented credential.
    pub async fn authenticate(&self, credential: Credential) -> Result<Actor, ServiceError> {
        self.application
            .authenticate(&credential)
            .await
            .map_err(Into::into)
    }

    /// Authorizes reading the operational counters: the operator only.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Application`] with `Forbidden` for any other actor.
    pub fn authorize_operational_read(
        &self,
        actor: &Actor,
    ) -> Result<OperationalReadGrant, ServiceError> {
        self.application
            .authorize_operational_read(actor)
            .map_err(Into::into)
    }

    /// Readiness check.
    pub async fn ready(&self) -> Result<(), ServiceError> {
        self.application.ready().await.map_err(Into::into)
    }

    /// Sends one copy through the application service.
    pub async fn send_copy(
        &self,
        actor: &Actor,
        command: SendCopyCommand,
    ) -> Result<Delivery, ServiceError> {
        self.application
            .send_copy(actor, command)
            .await
            .map_err(Into::into)
    }

    /// Accepts one exchange.
    pub async fn accept(
        &self,
        actor: &Actor,
        exchange_id: &ExchangeId,
        key: &IdempotencyKey,
    ) -> Result<AcceptanceResult, ServiceError> {
        self.application
            .accept(actor, exchange_id, key)
            .await
            .map_err(Into::into)
    }

    /// Reads one verified participant copy.
    pub async fn read_document(
        &self,
        actor: &Actor,
        exchange_id: &ExchangeId,
    ) -> Result<Vec<u8>, ServiceError> {
        self.application
            .read_document(actor, exchange_id)
            .await
            .map(|plaintext| plaintext.as_bytes().to_vec())
            .map_err(Into::into)
    }

    /// Lists one wallet's pending inbox.
    pub async fn list_inbox(
        &self,
        actor: &Actor,
        wallet: &WalletId,
    ) -> Result<Vec<ExchangeId>, ServiceError> {
        self.application
            .list_inbox(actor, wallet)
            .await
            .map_err(Into::into)
    }

    /// Verifies signed events and ciphertext commitments.
    pub async fn verify_audit(
        &self,
        actor: &Actor,
        expected: Option<Checkpoint>,
    ) -> Result<AuditReport, ServiceError> {
        self.application
            .verify_audit(actor, expected)
            .await
            .map_err(Into::into)
    }

    /// Returns the pinned public audit proof to an authorized auditor.
    pub fn audit_public_key(&self, actor: &Actor) -> Result<AuditPublicKey, ServiceError> {
        self.application.audit_public_key(actor).map_err(Into::into)
    }

    /// Selects or continues a bounded independent audit export.
    pub async fn export_audit_events(
        &self,
        actor: &Actor,
        request: AuditExportRequest,
    ) -> Result<AuditExportPage, ServiceError> {
        self.application
            .export_audit_events(actor, request)
            .await
            .map_err(Into::into)
    }

    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        self.application.adapters().exchanges.pool()
    }

    /// Releases the lease alone, as a process exit would; the pool stays open.
    #[cfg(feature = "test-support")]
    async fn release_lease(&self) {
        let lease = self
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(lease) = lease {
            lease.release().await;
        }
    }
}

/// The read-only startup checks on one pooled connection, in order, each failing with its own
/// step name when it observes a state that breaks it. A failed query observes nothing, so it
/// reports `database connection` at any check.
async fn check_database(pool: &sqlx::PgPool, schema: &str) -> Result<(), ServiceError> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| ServiceError::Initialization("database connection"))?;
    match schema_exists(&mut conn, schema).await {
        Ok(true) => {}
        Ok(false) => return Err(ServiceError::Initialization("database schema")),
        Err(_) => return Err(ServiceError::Initialization("database connection")),
    }
    match migration_state(&mut conn, schema).await {
        Ok(MigrationState::Current) => {}
        Ok(MigrationState::Mismatch) => {
            return Err(ServiceError::Initialization("database migrations mismatch"));
        }
        Ok(MigrationState::Pending) => {
            return Err(ServiceError::Initialization("database migrations pending"));
        }
        // A missing or unreadable ledger is already `Pending`; a failed read is a fault of the
        // connection, not a schema that needs migrating.
        Err(_) => return Err(ServiceError::Initialization("database connection")),
    }
    let current_schema: Option<String> = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| ServiceError::Initialization("database connection"))?;
    if current_schema.as_deref() != Some(schema) {
        return Err(ServiceError::Initialization("database schema"));
    }
    let role_privileges = ServiceError::Initialization("database role privileges");
    let (session, current) = session_roles(&mut conn)
        .await
        .map_err(|_| ServiceError::Initialization("database connection"))?;
    if session != current {
        return Err(role_privileges);
    }
    // A failed read means only that the rule could not be evaluated; it still refuses.
    match runtime_privilege_violations(&mut conn, &current).await {
        Ok(violations) if violations.is_empty() => Ok(()),
        Ok(_nonempty) => Err(role_privileges),
        Err(_) => Err(ServiceError::Initialization("database connection")),
    }
}

/// Counts used by the executable system evidence.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateStats {
    pub delivered: i64,
    pub events: i64,
    pub objects: usize,
    pub credits: i64,
    pub credit_entries: i64,
}

/// Test-only fixture composition. Default builds expose no deterministic key injection.
#[cfg(feature = "test-support")]
pub struct DemoHarness {
    /// `None` after [`DemoHarness::release_service`] or a failed restart.
    service: Option<Arc<DocchainService>>,
    database: DatabaseFixture,
    limits: Limits,
    after_put_new: PauseGate,
    before_send_commit: PauseGate,
    pub sender_credential: String,
    pub recipient_credential: String,
    pub unrelated_credential: String,
    /// An authenticated wallet, `wal_0000000000000004`, with no key bindings.
    pub unkeyed_credential: String,
    pub auditor_credential: String,
    pub operator_credential: String,
}

/// One test's invented key files, settings, PostgreSQL schema name, and document root.
///
/// The migration owner creates, migrates, inspects, and drops the schema; the service under
/// test uses only the runtime credential. Dropping it drops the schema, if it was created, and
/// removes the root, within five seconds, also when a test panics.
#[cfg(feature = "test-support")]
pub(crate) struct FixtureFiles {
    pub(crate) schema: String,
    pub(crate) root: std::path::PathBuf,
    pub(crate) object_root: std::path::PathBuf,
    /// The server's settings, with the runtime credential only.
    pub(crate) settings: Settings,
    /// The migration owner's settings.
    pub(crate) owner: MigrationSettings,
    /// Verifier-side copy of the product-owner trust anchor, separate from server settings.
    expected_audit_fingerprint: [u8; 32],
    /// Every `DOCCHAIN_` variable the server settings came from; no migration owner key.
    environment: Vec<(String, String)>,
    /// The `DOCCHAIN_` variables `docchain-migrate` reads; no runtime password.
    migration_environment: Vec<(String, String)>,
    credentials: [String; 6],
}

/// A fixture root being written. Dropping it while armed removes the root, so a fixture that
/// fails, or unwinds, after creating its root leaves nothing behind.
#[cfg(feature = "test-support")]
struct NewFixtureRoot(Option<std::path::PathBuf>);

#[cfg(feature = "test-support")]
impl NewFixtureRoot {
    /// Takes the root out, so that dropping the guard leaves it in place.
    fn disarm(mut self) -> std::path::PathBuf {
        self.0
            .take()
            .expect("the guard is armed until this call consumes it")
    }
}

#[cfg(feature = "test-support")]
impl Drop for NewFixtureRoot {
    fn drop(&mut self) {
        if let Some(root) = self.0.take() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// The process environment, keeping only Unicode variables.
#[cfg(feature = "test-support")]
fn process_environment() -> std::collections::HashMap<String, String> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

#[cfg(feature = "test-support")]
impl FixtureFiles {
    /// Writes the fixture files under a new temporary root and builds settings naming a new,
    /// not yet created, schema, from the process environment.
    pub(crate) fn write() -> Result<Self, ServiceError> {
        Self::write_with(process_environment(), None, &std::env::temp_dir())
    }

    /// As [`FixtureFiles::write`], from the `base` environment, and, with `revocation_from`,
    /// appending one authority-signed revocation of the recipient's encryption key, at the next
    /// registry sequence, that takes effect at that time.
    ///
    /// The fixture root is a new directory in `parent`.
    ///
    /// The runtime credential comes from the `DOCCHAIN_DATABASE__*` keys and the owner
    /// credential from the `DOCCHAIN_MIGRATION__*` keys; a missing key fails the fixture and
    /// names the key before anything is written. No `DOCCHAIN_MIGRATION__*` key reaches the
    /// server settings or the server environment.
    fn write_with(
        base: std::collections::HashMap<String, String>,
        revocation_from: Option<&str>,
        parent: &std::path::Path,
    ) -> Result<Self, ServiceError> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use serde_json::{Value, json};
        use std::{
            collections::HashMap,
            sync::atomic::{AtomicU64, Ordering},
        };

        // Refused before anything is written, so a refused fixture leaves no files behind.
        let present = |key: &str| base.get(key).is_some_and(|value| !value.is_empty());
        if !present("DOCCHAIN_DATABASE__USER") {
            return Err(ServiceError::Initialization(
                "test fixture requires DOCCHAIN_DATABASE__USER",
            ));
        }
        if !present("DOCCHAIN_DATABASE__PASSWORD") && !present("DOCCHAIN_DATABASE__PASSWORD_FILE") {
            return Err(ServiceError::Initialization(
                "test fixture requires DOCCHAIN_DATABASE__PASSWORD_FILE",
            ));
        }
        if !present("DOCCHAIN_MIGRATION__USER") {
            return Err(ServiceError::Initialization(
                "test fixture requires DOCCHAIN_MIGRATION__USER",
            ));
        }
        if !present("DOCCHAIN_MIGRATION__PASSWORD") && !present("DOCCHAIN_MIGRATION__PASSWORD_FILE")
        {
            return Err(ServiceError::Initialization(
                "test fixture requires DOCCHAIN_MIGRATION__PASSWORD_FILE",
            ));
        }

        static INSTANCE: AtomicU64 = AtomicU64::new(1);
        let suffix = INSTANCE.fetch_add(1, Ordering::Relaxed);
        let schema = format!("docchain_test_{}_{}", std::process::id(), suffix);
        let root = parent.join(&schema);
        std::fs::create_dir_all(&root).map_err(|_| ServiceError::Initialization("test fixture"))?;
        // From here every early return, and any unwind, removes the new root.
        let guard = NewFixtureRoot(Some(root.clone()));
        let fixture: Value =
            serde_json::from_str(include_str!("../../../tests/vectors/envelope-v1.json"))
                .map_err(|_| ServiceError::Initialization("test fixture"))?;
        let expected = &fixture["expected"];
        let bindings = expected["binding_records"]
            .as_array()
            .ok_or(ServiceError::Initialization("test fixture"))?
            .iter()
            .map(|record| {
                serde_json::from_str::<Value>(
                    record
                        .as_str()
                        .ok_or(ServiceError::Initialization("test fixture"))?,
                )
                .map_err(|_| ServiceError::Initialization("test fixture"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // A third wallet, whose ID sorts after both vector wallets, with its own
        // authority-signed keys.
        let third = crate::crypto::third_wallet()
            .map_err(|_| ServiceError::Initialization("test fixture"))?;
        let mut bindings = bindings;
        for record in &third.binding_records {
            bindings.push(
                serde_json::from_slice::<Value>(record)
                    .map_err(|_| ServiceError::Initialization("test fixture"))?,
            );
        }
        if let Some(not_before) = revocation_from {
            let mut body = bindings
                .get(2)
                .map(|record| record["body"].clone())
                .ok_or(ServiceError::Initialization("test fixture"))?;
            let next = u64::try_from(bindings.len())
                .map_err(|_| ServiceError::Initialization("test fixture"))?
                .saturating_add(1);
            body["registry_sequence"] = json!(next);
            body["state"] = json!("revoked");
            body["not_before"] = json!(not_before);
            let record = crate::crypto::authority_signed_record(&body)
                .map_err(|_| ServiceError::Initialization("test fixture"))?;
            bindings.push(
                serde_json::from_slice::<Value>(&record)
                    .map_err(|_| ServiceError::Initialization("test fixture"))?,
            );
        }
        write(
            &root.join("authority.key"),
            expected["registry_public_key"]
                .as_str()
                .ok_or(ServiceError::Initialization("test fixture"))?,
        )?;
        write(
            &root.join("bindings.json"),
            &serde_json::to_string(&bindings)
                .map_err(|_| ServiceError::Initialization("test fixture"))?,
        )?;
        let sequential = |start: u8| {
            std::array::from_fn::<_, 32, _>(|index| {
                start.saturating_add(u8::try_from(index).unwrap_or(0))
            })
        };
        write(
            &root.join("signing.key"),
            &URL_SAFE_NO_PAD.encode(sequential(0x20)),
        )?;
        write(
            &root.join("sender-encryption.key"),
            &URL_SAFE_NO_PAD.encode(sequential(0x40)),
        )?;
        write(
            &root.join("recipient-encryption.key"),
            &URL_SAFE_NO_PAD.encode(sequential(0x60)),
        )?;
        write(
            &root.join("third-signing.key"),
            &URL_SAFE_NO_PAD.encode(third.signing_seed),
        )?;
        write(
            &root.join("third-encryption.key"),
            &URL_SAFE_NO_PAD.encode(third.encryption_ikm),
        )?;
        write(
            &root.join("audit.key"),
            &URL_SAFE_NO_PAD.encode(sequential(0xb0)),
        )?;
        let audit_key = AuditKey::load(&root.join("audit.key"))
            .map_err(|_| ServiceError::Initialization("test fixture"))?;
        let audit_public_key = audit_key
            .public_key()
            .map_err(|_| ServiceError::Initialization("test fixture"))?;
        let expected_audit_fingerprint = sha256(&audit_public_key);
        let audit_fingerprint = URL_SAFE_NO_PAD.encode(expected_audit_fingerprint);
        let sender_credential = "synthetic-sender-credential".to_owned();
        let recipient_credential = "synthetic-recipient-credential".to_owned();
        let unrelated_credential = "synthetic-unrelated-credential".to_owned();
        let unkeyed_credential = "synthetic-unkeyed-credential".to_owned();
        let auditor_credential = "synthetic-auditor-credential".to_owned();
        let operator_credential = "synthetic-operator-credential".to_owned();
        write(
            &root.join("identities.json"),
            &json!({
                "wallets": {
                    "wal_0000000000000001": sender_credential,
                    "wal_0000000000000002": recipient_credential,
                    "wal_0000000000000003": unrelated_credential,
                    "wal_0000000000000004": unkeyed_credential
                },
                "auditor": auditor_credential, "operator": operator_credential
            })
            .to_string(),
        )?;

        let object_root = root.join("objects");
        let mut values: HashMap<String, String> = base;
        for (key, value) in [
            ("DOCCHAIN_DATABASE__SCHEMA", schema.clone()),
            (
                "DOCCHAIN_DOCUMENT_STORE__ROOT",
                object_root.display().to_string(),
            ),
            (
                "DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE",
                root.join("authority.key").display().to_string(),
            ),
            (
                "DOCCHAIN_KEYS__BINDINGS_FILE",
                root.join("bindings.json").display().to_string(),
            ),
            (
                "DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES",
                format!(
                    "{},{}",
                    root.join("signing.key").display(),
                    root.join("third-signing.key").display()
                ),
            ),
            (
                "DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES",
                format!(
                    "{},{},{}",
                    root.join("sender-encryption.key").display(),
                    root.join("recipient-encryption.key").display(),
                    root.join("third-encryption.key").display()
                ),
            ),
            (
                "DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE",
                root.join("audit.key").display().to_string(),
            ),
            (
                "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT",
                audit_fingerprint,
            ),
            (
                "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
                root.join("identities.json").display().to_string(),
            ),
        ] {
            values.insert(key.to_owned(), value);
        }
        let migration_environment: Vec<(String, String)> = values
            .iter()
            .filter(|(key, _)| {
                key.starts_with("DOCCHAIN_MIGRATION__")
                    || [
                        "DOCCHAIN_DATABASE__HOST",
                        "DOCCHAIN_DATABASE__PORT",
                        "DOCCHAIN_DATABASE__NAME",
                        "DOCCHAIN_DATABASE__SCHEMA",
                        "DOCCHAIN_DATABASE__USER",
                    ]
                    .contains(&key.as_str())
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let owner = MigrationSettings::from_map(migration_environment.iter().cloned().collect())
            .map_err(|_| ServiceError::Initialization("test fixture migration owner settings"))?;
        values.retain(|key, _| !key.starts_with("DOCCHAIN_MIGRATION__"));
        let environment = values
            .iter()
            .filter(|(key, _)| key.starts_with("DOCCHAIN_"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let settings = Settings::from_map(values)
            .map_err(|_| ServiceError::Initialization("test fixture runtime settings"))?;

        // Nothing fallible remains: the complete fixture's own `Drop` removes the root.
        Ok(Self {
            schema,
            root: guard.disarm(),
            object_root,
            settings,
            owner,
            expected_audit_fingerprint,
            environment,
            migration_environment,
            credentials: [
                sender_credential,
                recipient_credential,
                unrelated_credential,
                unkeyed_credential,
                auditor_credential,
                operator_credential,
            ],
        })
    }

    /// Options for the migration owner's connections to the fixture schema.
    fn owner_options(&self) -> PgConnectOptions {
        migration_connect_options(&self.owner).application_name("docchain-test-owner")
    }

    /// A pool of the migration owner's connections, refused when its session is a superuser's.
    pub(crate) async fn owner_pool(&self) -> Result<sqlx::PgPool, ServiceError> {
        guarded_pool(
            self.owner_options(),
            "test fixture refuses a superuser as DOCCHAIN_MIGRATION__USER",
        )
        .await
    }

    /// A pool of runtime connections confined to the fixture's schema, as the service connects,
    /// refused when its session is a superuser's.
    pub(crate) async fn runtime_pool(&self) -> Result<sqlx::PgPool, ServiceError> {
        guarded_pool(
            connect_options(&self.settings.database).application_name("docchain-test-runtime"),
            "test fixture refuses a superuser as DOCCHAIN_DATABASE__USER",
        )
        .await
    }

    /// Creates the fixture's schema, owned by the migration owner.
    pub(crate) async fn create_schema(&self, owner: &sqlx::PgPool) -> Result<(), ServiceError> {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE SCHEMA {}",
            self.schema
        )))
        .execute(owner)
        .await
        .map(|_| ())
        .map_err(|_| ServiceError::Initialization("test fixture schema"))
    }

    /// Applies every embedded migration as the owner. A failed run's connection is closed, so
    /// SQLx's database-wide migration lock is released.
    pub(crate) async fn migrate(&self, owner: &sqlx::PgPool) -> Result<(), ServiceError> {
        let mut conn = owner
            .acquire()
            .await
            .map_err(|_| ServiceError::Initialization("test fixture migration"))?;
        match crate::store::migrate_schema(&mut conn).await {
            Ok(()) => Ok(()),
            Err(_) => {
                let _ = conn.close().await;
                Err(ServiceError::Initialization("test fixture migration"))
            }
        }
    }

    /// Whether a schema with the fixture's name exists.
    #[cfg(test)]
    pub(crate) async fn schema_exists(&self) -> Result<bool, ServiceError> {
        schema_exists_as(self.owner_options(), &self.schema).await
    }
}

/// Connects a pool, then refuses it unless neither the session nor the current role of its
/// connection is a superuser. `refusal` names the key that configured the role.
#[cfg(feature = "test-support")]
pub(crate) async fn guarded_pool(
    options: PgConnectOptions,
    refusal: &'static str,
) -> Result<sqlx::PgPool, ServiceError> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await
        .map_err(|_| ServiceError::Initialization("test fixture connection"))?;
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| ServiceError::Initialization("test fixture connection"))?;
    if crate::store::session_is_superuser(&mut conn).await {
        drop(conn);
        pool.close().await;
        return Err(ServiceError::Initialization(refusal));
    }
    Ok(pool)
}

#[cfg(all(test, feature = "test-support"))]
async fn schema_exists_as(options: PgConnectOptions, schema: &str) -> Result<bool, ServiceError> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|_| ServiceError::Inspection)?;
    let exists = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)")
        .bind(schema)
        .fetch_one(&admin)
        .await
        .map_err(|_| ServiceError::Inspection);
    admin.close().await;
    exists
}

/// Polls `pg_locks` from `observer`, every 20 ms for at most 10 s, until a session waits for
/// an ACCESS SHARE lock on `relation`, a schema-qualified table, and returns that session's pid.
/// The observed row is the synchronization; the interval only paces the reads.
///
/// # Panics
///
/// When no session waits on `relation` within 10 s, or the catalog read fails.
#[cfg(all(test, feature = "test-support"))]
pub(crate) async fn access_share_waiter(observer: &sqlx::PgPool, relation: &str) -> i32 {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiter: Option<i32> = sqlx::query_scalar(
            "SELECT pid FROM pg_locks WHERE locktype = 'relation' \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
             AND relation = to_regclass($1) AND mode = 'AccessShareLock' AND NOT granted \
             ORDER BY pid LIMIT 1",
        )
        .bind(relation)
        .fetch_optional(observer)
        .await
        .expect("lock waits");
        if let Some(pid) = waiter {
            return pid;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no session waited on {relation} within 10 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[cfg(feature = "test-support")]
impl Drop for FixtureFiles {
    fn drop(&mut self) {
        let options = self.owner_options();
        let schema = self.schema.clone();
        let root = self.root.clone();
        // A separate thread and runtime, so cleanup also works while a test's own runtime is
        // unwinding from a panic.
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(runtime) = runtime {
                runtime.block_on(async move {
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        if let Ok(mut admin) = sqlx::ConnectOptions::connect(&options).await {
                            // Cleanup never runs with a superuser's rights.
                            if !crate::store::session_is_superuser(&mut admin).await {
                                let statement = format!("DROP SCHEMA IF EXISTS {schema} CASCADE");
                                let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                                    .execute(&mut admin)
                                    .await;
                            }
                            let _ = sqlx::Connection::close(admin).await;
                        }
                    })
                    .await;
                });
            }
            let _ = std::fs::remove_dir_all(root);
        });
        let _ = cleanup.join();
    }
}

/// A disposable schema that the migration owner created and has not yet migrated, with its
/// fixture files and one pool for each credential. Dropping it drops the schema and the files.
#[cfg(feature = "test-support")]
pub struct DatabaseFixture {
    fixture: FixtureFiles,
    owner: sqlx::PgPool,
    runtime: sqlx::PgPool,
}

#[cfg(feature = "test-support")]
impl DatabaseFixture {
    /// Writes fixture files from the process environment, opens both pools, refusing a
    /// superuser on either, and creates the schema as the owner.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Initialization`] naming the step, or the missing or refused key.
    pub async fn new() -> Result<Self, ServiceError> {
        Self::create(FixtureFiles::write()?).await
    }

    async fn create(fixture: FixtureFiles) -> Result<Self, ServiceError> {
        let owner = fixture.owner_pool().await?;
        let runtime = fixture.runtime_pool().await?;
        fixture.create_schema(&owner).await?;
        Ok(Self {
            fixture,
            owner,
            runtime,
        })
    }

    /// Applies every embedded migration as the owner.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Initialization`] when a migration fails.
    pub async fn migrate(&self) -> Result<(), ServiceError> {
        self.fixture.migrate(&self.owner).await
    }

    /// The `DOCCHAIN_` environment that runs the server binary against this schema, document
    /// root, and key files. It holds the runtime credential and no migration owner key.
    pub fn server_environment(&self) -> Vec<(String, String)> {
        self.fixture.environment.clone()
    }

    /// The `DOCCHAIN_` environment that runs `docchain-migrate` against this schema. It holds
    /// the owner credential and not the runtime password.
    pub fn migration_environment(&self) -> Vec<(String, String)> {
        self.fixture.migration_environment.clone()
    }

    /// The migration owner's pool, for inspection and tampering.
    pub const fn owner_pool(&self) -> &sqlx::PgPool {
        &self.owner
    }

    /// The runtime role's pool, confined to this schema.
    pub const fn runtime_pool(&self) -> &sqlx::PgPool {
        &self.runtime
    }

    /// This fixture's schema.
    pub fn schema(&self) -> &str {
        &self.fixture.schema
    }

    /// The runtime role's name.
    pub fn runtime_role(&self) -> &str {
        &self.fixture.settings.database.user
    }

    /// The classes of the runtime privilege rule that the runtime role breaks, as the server
    /// checks them at startup, from a runtime connection.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Inspection`] when the catalogs cannot be read.
    pub async fn runtime_privilege_violations(&self) -> Result<Vec<String>, ServiceError> {
        let mut conn = self
            .runtime
            .acquire()
            .await
            .map_err(|_| ServiceError::Inspection)?;
        runtime_privilege_violations(&mut conn, self.runtime_role())
            .await
            .map(|violations| {
                violations
                    .iter()
                    .map(|violation| format!("{violation:?}"))
                    .collect()
            })
            .map_err(|_| ServiceError::Inspection)
    }
}

#[cfg(feature = "test-support")]
impl DemoHarness {
    pub async fn new() -> Result<Self, ServiceError> {
        Self::new_with_limits(Limits::default()).await
    }

    pub async fn new_with_limits(limits: Limits) -> Result<Self, ServiceError> {
        Self::compose_fixture(FixtureFiles::write()?, limits).await
    }

    /// A harness whose key registry also holds an authority-signed revocation of the recipient's
    /// encryption key, appended at the next sequence and taking effect at
    /// `2099-01-01T00:00:00Z`.
    pub async fn with_scheduled_revocation() -> Result<Self, ServiceError> {
        Self::compose_fixture(
            FixtureFiles::write_with(
                process_environment(),
                Some("2099-01-01T00:00:00Z"),
                &std::env::temp_dir(),
            )?,
            Limits::default(),
        )
        .await
    }

    /// Creates and migrates the schema as the owner, then composes the service as the runtime
    /// role, with every startup check.
    async fn compose_fixture(fixture: FixtureFiles, limits: Limits) -> Result<Self, ServiceError> {
        let database = DatabaseFixture::create(fixture).await?;
        database.migrate().await?;
        let after_put_new = PauseGate::default();
        let before_send_commit = PauseGate::default();
        let service = DocchainService::compose_with(
            &database.fixture.settings,
            limits,
            StartOptions {
                after_put_new: Some(after_put_new.clone()),
                before_send_commit: Some(before_send_commit.clone()),
                ..StartOptions::default()
            },
        )
        .await?;
        let [
            sender_credential,
            recipient_credential,
            unrelated_credential,
            unkeyed_credential,
            auditor_credential,
            operator_credential,
        ] = database.fixture.credentials.clone();
        Ok(Self {
            service: Some(Arc::new(service)),
            database,
            limits,
            after_put_new,
            before_send_commit,
            sender_credential,
            recipient_credential,
            unrelated_credential,
            unkeyed_credential,
            auditor_credential,
            operator_credential,
        })
    }

    /// The `DOCCHAIN_` environment that runs the server binary against this harness's own
    /// schema, document root, and key files. It holds no migration owner key.
    pub fn server_environment(&self) -> Vec<(String, String)> {
        self.database.server_environment()
    }

    /// This harness's migrated schema, with the owner and runtime pools.
    pub const fn database(&self) -> &DatabaseFixture {
        &self.database
    }

    /// The migration owner's pool, which test inspection and tampering use.
    pub const fn owner_pool(&self) -> &sqlx::PgPool {
        &self.database.owner
    }

    /// The runtime role's pool.
    pub const fn runtime_pool(&self) -> &sqlx::PgPool {
        &self.database.runtime
    }

    /// This harness's schema name and fixture root, for cleanup checks.
    pub fn fixture_location(&self) -> (String, std::path::PathBuf) {
        (
            self.database.fixture.schema.clone(),
            self.database.fixture.root.clone(),
        )
    }

    /// The running in-process service.
    ///
    /// # Panics
    ///
    /// After [`DemoHarness::release_service`], or a restart that failed, until a restart
    /// succeeds.
    pub fn service(&self) -> Arc<DocchainService> {
        Arc::clone(
            self.service
                .as_ref()
                .expect("the harness's service is running; restart it after a release"),
        )
    }

    fn running(&self) -> Result<&DocchainService, ServiceError> {
        self.service.as_deref().ok_or(ServiceError::Inspection)
    }

    /// The document store root the service and the server binary use.
    pub fn document_root(&self) -> std::path::PathBuf {
        self.database.fixture.object_root.clone()
    }

    /// The gate every send of this harness's services passes after writing its object.
    pub fn after_put_new_gate(&self) -> PauseGate {
        self.after_put_new.clone()
    }

    /// The gate every send of this harness's services passes inside its transaction, just
    /// before `COMMIT`.
    pub fn before_send_commit_gate(&self) -> PauseGate {
        self.before_send_commit.clone()
    }

    /// Start options for this harness's schema and root, with its two send gates.
    fn with_gates(&self, options: StartOptions) -> StartOptions {
        StartOptions {
            after_put_new: Some(self.after_put_new.clone()),
            before_send_commit: Some(self.before_send_commit.clone()),
            ..options
        }
    }

    /// Stops the in-process service as a process exit would: its lease session and lock file
    /// close, and its pool closes. Returns once PostgreSQL no longer shows the schema lock.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Inspection`] when no service runs, when another `Arc` to it remains
    /// (the service is kept running), or when the schema lock is still held after five seconds.
    pub async fn release_service(&mut self) -> Result<(), ServiceError> {
        let service = self.service.take().ok_or(ServiceError::Inspection)?;
        let service = match Arc::try_unwrap(service) {
            Ok(service) => service,
            Err(shared) => {
                self.service = Some(shared);
                return Err(ServiceError::Inspection);
            }
        };
        service.release_lease().await;
        service
            .application
            .adapters()
            .exchanges
            .pool()
            .close()
            .await;
        drop(service);
        self.wait_for_schema_lock_release().await
    }

    /// Releases only the running service's lease, as its process exit would, while its pool and
    /// any open transaction stay. Returns once PostgreSQL no longer shows the schema lock.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Inspection`] when no service runs or the lock stays held.
    pub async fn release_lease(&self) -> Result<(), ServiceError> {
        self.running()?.release_lease().await;
        self.wait_for_schema_lock_release().await
    }

    /// Releases the running service, if any, then composes a new one on the same schema and
    /// root with `options`, and returns its sweep report. When composition fails, no service
    /// runs until a later restart succeeds.
    ///
    /// # Errors
    ///
    /// The release's error, or the composition's [`ServiceError::Initialization`].
    pub async fn restart(&mut self, options: StartOptions) -> Result<StoreSweep, ServiceError> {
        if self.service.is_some() {
            self.release_service().await?;
        }
        let service = DocchainService::compose_with(
            &self.database.fixture.settings,
            self.limits,
            self.with_gates(options),
        )
        .await?;
        let report = service.sweep_report();
        self.service = Some(Arc::new(service));
        Ok(report)
    }

    /// A composition of a second, independent service on this harness's schema and root, as
    /// another server process would start; it can be spawned onto its own task.
    pub fn start_instance(
        &self,
        options: StartOptions,
    ) -> impl std::future::Future<Output = Result<DocchainService, ServiceError>> + Send + 'static
    {
        let settings = self.database.fixture.settings.clone();
        let limits = self.limits;
        let options = self.with_gates(options);
        async move { DocchainService::compose_with(&settings, limits, options).await }
    }

    /// Polls, as the owner, until no session holds this schema's lease lock, for at most five
    /// seconds.
    async fn wait_for_schema_lock_release(&self) -> Result<(), ServiceError> {
        let started = std::time::Instant::now();
        loop {
            let held: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks l \
                 WHERE l.locktype = 'advisory' AND l.objsubid = 1 \
                 AND l.classid::bigint = x'44435357'::bigint \
                 AND l.objid::bigint = (SELECT oid::bigint FROM pg_catalog.pg_namespace \
                 WHERE nspname = $1))",
            )
            .bind(&self.database.fixture.schema)
            .fetch_one(&self.database.owner)
            .await
            .map_err(|_| ServiceError::Inspection)?;
            if !held {
                return Ok(());
            }
            if started.elapsed() > std::time::Duration::from_secs(5) {
                return Err(ServiceError::Inspection);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    pub async fn actor(&self, credential: &str) -> Result<Actor, ServiceError> {
        self.running()?
            .authenticate(Credential::new(credential.to_owned()))
            .await
    }
    pub async fn send_copy(
        &self,
        actor: &Actor,
        command: SendCopyCommand,
    ) -> Result<Delivery, ServiceError> {
        self.running()?.send_copy(actor, command).await
    }
    pub async fn accept(
        &self,
        actor: &Actor,
        exchange: &ExchangeId,
        key: &IdempotencyKey,
    ) -> Result<AcceptanceResult, ServiceError> {
        self.running()?.accept(actor, exchange, key).await
    }
    pub async fn read_document(
        &self,
        actor: &Actor,
        exchange: &ExchangeId,
    ) -> Result<Vec<u8>, ServiceError> {
        self.running()?.read_document(actor, exchange).await
    }
    pub async fn list_inbox(
        &self,
        actor: &Actor,
        wallet: &WalletId,
    ) -> Result<Vec<ExchangeId>, ServiceError> {
        self.running()?.list_inbox(actor, wallet).await
    }
    pub async fn verify_audit(
        &self,
        expected: Option<Checkpoint>,
    ) -> Result<AuditReport, ServiceError> {
        let actor = self.actor(&self.auditor_credential).await?;
        self.running()?.verify_audit(&actor, expected).await
    }
    /// The fixture-owned trust anchor supplied independently of any HTTP response.
    pub fn expected_audit_fingerprint(&self) -> [u8; 32] {
        self.database.fixture.expected_audit_fingerprint
    }
    pub async fn audit_public_key(&self) -> Result<AuditPublicKey, ServiceError> {
        let actor = self.actor(&self.auditor_credential).await?;
        self.running()?.audit_public_key(&actor)
    }
    pub async fn export_audit_events(
        &self,
        request: AuditExportRequest,
    ) -> Result<AuditExportPage, ServiceError> {
        let actor = self.actor(&self.auditor_credential).await?;
        self.running()?.export_audit_events(&actor, request).await
    }
    pub async fn stats(&self) -> Result<StateStats, ServiceError> {
        let pool = &self.database.owner;
        let delivered = sqlx::query_scalar("SELECT COUNT(*) FROM exchanges")
            .fetch_one(pool)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        let events = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(pool)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        let credits = sqlx::query_scalar("SELECT COUNT(*) FROM credit_transactions")
            .fetch_one(pool)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        let credit_entries = sqlx::query_scalar("SELECT COUNT(*) FROM credit_entries")
            .fetch_one(pool)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        let mut directory = tokio::fs::read_dir(&self.database.fixture.object_root)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        // Only regular files with object names: control files, temporaries, and foreign entries
        // are not objects.
        let mut objects = 0_usize;
        while let Some(entry) = directory
            .next_entry()
            .await
            .map_err(|_| ServiceError::Inspection)?
        {
            let is_file = entry
                .file_type()
                .await
                .map_err(|_| ServiceError::Inspection)?
                .is_file();
            if is_file
                && docchain_domain::ObjectId::new(entry.file_name().to_string_lossy()).is_ok()
            {
                objects = objects.saturating_add(1);
            }
        }
        Ok(StateStats {
            delivered,
            events,
            objects,
            credits,
            credit_entries,
        })
    }
    pub async fn envelope(&self, exchange: &ExchangeId) -> Result<Vec<u8>, ServiceError> {
        let object: String =
            sqlx::query_scalar("SELECT object_id FROM exchanges WHERE exchange_id = $1")
                .bind(exchange.as_str())
                .fetch_one(&self.database.owner)
                .await
                .map_err(|_| ServiceError::Inspection)?;
        tokio::fs::read(self.database.fixture.object_root.join(object))
            .await
            .map_err(|_| ServiceError::Inspection)
    }
    pub async fn object_exists(&self, object: &docchain_domain::ObjectId) -> bool {
        tokio::fs::metadata(self.database.fixture.object_root.join(object.as_str()))
            .await
            .is_ok()
    }
    pub async fn remove_document_root(&self) -> Result<(), ServiceError> {
        tokio::fs::remove_dir_all(&self.database.fixture.object_root)
            .await
            .map_err(|_| ServiceError::Inspection)
    }
    pub async fn audit_events(&self) -> Result<Vec<docchain_domain::AuditEvent>, ServiceError> {
        let mut page = self
            .running()?
            .application
            .adapters()
            .exchanges
            .page(AuditReadRequest {
                snapshot: None,
                after_sequence: 0,
                limit: 500,
            })
            .await
            .map_err(|_| ServiceError::Inspection)?;
        let snapshot = page.snapshot;
        let mut events = Vec::new();
        loop {
            let has_more = page.has_more;
            let progressed = !page.events.is_empty();
            events.extend(page.events);
            if !has_more {
                return Ok(events);
            }
            if !progressed {
                return Err(ServiceError::Inspection);
            }
            let after_sequence = events
                .last()
                .map(|event| event.sequence)
                .ok_or(ServiceError::Inspection)?;
            page = self
                .running()?
                .application
                .adapters()
                .exchanges
                .page(AuditReadRequest {
                    snapshot: Some(snapshot),
                    after_sequence,
                    limit: 500,
                })
                .await
                .map_err(|_| ServiceError::Inspection)?;
        }
    }
    pub async fn alter_envelope(&self, exchange: &ExchangeId) -> Result<(), ServiceError> {
        let object: String =
            sqlx::query_scalar("SELECT object_id FROM exchanges WHERE exchange_id = $1")
                .bind(exchange.as_str())
                .fetch_one(&self.database.owner)
                .await
                .map_err(|_| ServiceError::Inspection)?;
        let path = self.database.fixture.object_root.join(object);
        let mut bytes = tokio::fs::read(&path)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        if let Some(byte) = bytes.first_mut() {
            *byte ^= 1;
        }
        tokio::fs::write(path, bytes)
            .await
            .map_err(|_| ServiceError::Inspection)
    }
    pub async fn truncate_last_event(&self) -> Result<(), ServiceError> {
        self.tamper_as_owner(
            "DELETE FROM audit_events WHERE sequence = (SELECT MAX(sequence) FROM audit_events)",
        )
        .await
        .map(|_| ())
    }
    /// Tampers with events the way the table owner could: the append-only refusal triggers on
    /// `audit_events` are disabled only inside this transaction, and re-enabled before it commits.
    pub async fn tamper_as_owner(&self, statement: &str) -> Result<u64, ServiceError> {
        let mut transaction = self
            .database
            .owner
            .begin()
            .await
            .map_err(|_| ServiceError::Inspection)?;
        for trigger in [
            "audit_events_refuse_update_delete",
            "audit_events_refuse_truncate",
        ] {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "ALTER TABLE audit_events DISABLE TRIGGER {trigger}"
            )))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        }
        let affected = sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServiceError::Inspection)?
            .rows_affected();
        for trigger in [
            "audit_events_refuse_update_delete",
            "audit_events_refuse_truncate",
        ] {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "ALTER TABLE audit_events ENABLE ALWAYS TRIGGER {trigger}"
            )))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServiceError::Inspection)?;
        Ok(affected)
    }
    /// Runs one statement as the migration owner in its own transaction, optionally after
    /// `SET LOCAL session_replication_role = replica`, and returns the rows it affected or the
    /// SQLSTATE the statement, the replica setting, or COMMIT failed with. The owner is not a
    /// superuser, so the replica setting itself is refused.
    pub async fn sqlstate_of(&self, statement: &str, replica: bool) -> Result<u64, String> {
        let mut transaction = self
            .database
            .owner
            .begin()
            .await
            .map_err(|_| "connection".to_owned())?;
        if replica {
            sqlx::raw_sql("SET LOCAL session_replication_role = replica")
                .execute(&mut *transaction)
                .await
                .map_err(|error| sqlstate(&error))?;
        }
        let result = sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
            .execute(&mut *transaction)
            .await;
        match result {
            Ok(done) => {
                transaction
                    .commit()
                    .await
                    .map_err(|error| sqlstate(&error))?;
                Ok(done.rows_affected())
            }
            Err(error) => Err(sqlstate(&error)),
        }
    }
    /// Runs one statement on an append-only table the way its owner could: the table's
    /// `<table>_refuse_update_delete` trigger is disabled inside the statement's transaction, so
    /// only the other constraints and triggers, such as the deferred credit balance check, still
    /// apply. Returns the rows affected, or the SQLSTATE the statement or its COMMIT failed with.
    ///
    /// PostgreSQL refuses `ALTER TABLE` while deferred trigger events are pending, so the refusal
    /// is re-enabled, with `ENABLE ALWAYS`, right after the transaction ends. A failed statement
    /// or COMMIT also rolls the disabling back.
    pub async fn sqlstate_as_owner(&self, table: &str, statement: &str) -> Result<u64, String> {
        const APPEND_ONLY: [&str; 4] = [
            "audit_events",
            "acceptances",
            "credit_transactions",
            "credit_entries",
        ];
        if !APPEND_ONLY.contains(&table) {
            return Err("not an append-only table".to_owned());
        }
        let pool = &self.database.owner;
        let mut transaction = pool.begin().await.map_err(|error| sqlstate(&error))?;
        let disabled = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE {table} DISABLE TRIGGER {table}_refuse_update_delete"
        )))
        .execute(&mut *transaction)
        .await;
        let executed = match disabled {
            Ok(_) => {
                sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
                    .execute(&mut *transaction)
                    .await
            }
            Err(error) => Err(error),
        };
        let outcome = match executed {
            Ok(done) => transaction
                .commit()
                .await
                .map(|()| done.rows_affected())
                .map_err(|error| sqlstate(&error)),
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(sqlstate(&error))
            }
        };
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_refuse_update_delete"
        )))
        .execute(pool)
        .await
        .map_err(|error| sqlstate(&error))?;
        outcome
    }
    /// Runs statements as the runtime role in one transaction and returns the rows the last
    /// affected, or the SQLSTATE a statement or COMMIT failed with. Without `commit` the
    /// transaction always rolls back, so nothing the runtime role creates outlives it.
    pub async fn sqlstate_as_runtime(&self, statements: &str, commit: bool) -> Result<u64, String> {
        let mut transaction = self
            .database
            .runtime
            .begin()
            .await
            .map_err(|error| sqlstate(&error))?;
        let executed = sqlx::raw_sql(sqlx::AssertSqlSafe(statements.to_owned()))
            .execute(&mut *transaction)
            .await;
        match executed {
            Ok(done) if commit => transaction
                .commit()
                .await
                .map(|()| done.rows_affected())
                .map_err(|error| sqlstate(&error)),
            Ok(done) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|error| sqlstate(&error))?;
                Ok(done.rows_affected())
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(sqlstate(&error))
            }
        }
    }
    /// Runs one statement as the migration owner, bypassing every use case, so tests can
    /// inspect or tamper with stored rows the way the table owner could.
    pub async fn execute_unchecked(&self, statement: &str) -> Result<u64, ServiceError> {
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
            .execute(&self.database.owner)
            .await
            .map(|done| done.rows_affected())
            .map_err(|_| ServiceError::Inspection)
    }
}

/// The SQLSTATE a database error carries, or `none`.
#[cfg(feature = "test-support")]
fn sqlstate(error: &sqlx::Error) -> String {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .map_or_else(|| "none".to_owned(), |code| code.into_owned())
}

#[cfg(feature = "test-support")]
fn write(path: &std::path::Path, value: &str) -> Result<(), ServiceError> {
    std::fs::write(path, value).map_err(|_| ServiceError::Initialization("test fixture"))
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    async fn exists(options: PgConnectOptions, schema: &str) -> Option<bool> {
        schema_exists_as(options, schema).await.ok()
    }

    #[tokio::test]
    async fn composition_rejects_a_mismatched_audit_public_key_pin() {
        let mut fixture = FixtureFiles::write().expect("fixture");
        fixture.settings.keys.audit_public_key_fingerprint = [0; 32];
        let database = DatabaseFixture::create(fixture).await.expect("schema");
        database.migrate().await.expect("migrations");
        assert!(matches!(
            DocchainService::compose(&database.fixture.settings).await,
            Err(ServiceError::Initialization("audit public key fingerprint"))
        ));
    }

    /// Writes invented password files into `secrets` and returns the four credential keys
    /// that name them.
    fn invented_credentials(secrets: &std::path::Path) -> HashMap<String, String> {
        std::fs::create_dir_all(secrets).expect("secret directory");
        let runtime_file = secrets.join("runtime");
        let owner_file = secrets.join("owner");
        std::fs::write(&runtime_file, "invented-runtime-password").expect("runtime file");
        std::fs::write(&owner_file, "invented-owner-password").expect("owner file");
        [
            ("DOCCHAIN_DATABASE__USER", "docchain_runtime".to_owned()),
            (
                "DOCCHAIN_DATABASE__PASSWORD_FILE",
                runtime_file.display().to_string(),
            ),
            ("DOCCHAIN_MIGRATION__USER", "docchain_owner".to_owned()),
            (
                "DOCCHAIN_MIGRATION__PASSWORD_FILE",
                owner_file.display().to_string(),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
    }

    #[test]
    fn server_environments_never_carry_migration_owner_keys() {
        let secrets = std::env::temp_dir().join(format!(
            "docchain_harness_environment_{}",
            std::process::id()
        ));
        let base = invented_credentials(&secrets);

        let fixture = FixtureFiles::write_with(base, None, &std::env::temp_dir()).expect("fixture");
        // The in-process settings refuse any owner key, so building them proves its absence.
        assert!(
            fixture
                .environment
                .iter()
                .all(|(key, _)| !key.starts_with("DOCCHAIN_MIGRATION__"))
        );
        assert_eq!(fixture.settings.database.user, "docchain_runtime");
        assert_eq!(fixture.owner.owner, "docchain_owner");
        assert_eq!(fixture.owner.runtime_role, "docchain_runtime");
        assert!(
            fixture
                .migration_environment
                .iter()
                .all(|(key, _)| !key.starts_with("DOCCHAIN_DATABASE__PASSWORD"))
        );
        assert!(
            fixture
                .migration_environment
                .iter()
                .any(|(key, _)| key == "DOCCHAIN_MIGRATION__PASSWORD_FILE")
        );
        drop(fixture);
        std::fs::remove_dir_all(secrets).expect("remove secrets");
    }

    #[test]
    fn refused_fixtures_leave_nothing_behind() {
        let secrets = std::env::temp_dir().join(format!(
            "docchain_harness_refusal_secrets_{}",
            std::process::id()
        ));
        let base = invented_credentials(&secrets);
        // A directory of this test's own: the shared temporary directory also holds the
        // fixtures of tests running in parallel.
        let parent =
            std::env::temp_dir().join(format!("docchain_harness_refusals_{}", std::process::id()));
        std::fs::create_dir_all(&parent).expect("fixture parent");
        let entries = || std::fs::read_dir(&parent).expect("fixture parent").count();

        // Each missing credential key fails the fixture, naming the key, and writes nothing.
        for key in [
            "DOCCHAIN_DATABASE__USER",
            "DOCCHAIN_DATABASE__PASSWORD_FILE",
            "DOCCHAIN_MIGRATION__USER",
            "DOCCHAIN_MIGRATION__PASSWORD_FILE",
        ] {
            let mut incomplete = base.clone();
            incomplete.remove(key);
            assert_eq!(entries(), 0, "{key}");
            match FixtureFiles::write_with(incomplete, None, &parent) {
                Err(ServiceError::Initialization(step)) => {
                    assert_eq!(step, format!("test fixture requires {key}"));
                }
                Err(other) => panic!("{key}: {other:?}"),
                Ok(_) => panic!("{key}: fixture without the key"),
            }
            assert_eq!(entries(), 0, "{key} left files behind");
        }

        // With every credential key present, settings refused after the root exists still
        // leave nothing behind.
        for (key, value, refusal) in [
            (
                "DOCCHAIN_MIGRATION__USER",
                "docchain_runtime",
                "test fixture migration owner settings",
            ),
            (
                "DOCCHAIN_DATABASE__MAX_CONNECTIONS",
                "1",
                "test fixture runtime settings",
            ),
        ] {
            let mut refused = base.clone();
            refused.insert(key.to_owned(), value.to_owned());
            assert_eq!(entries(), 0, "{key}");
            match FixtureFiles::write_with(refused, None, &parent) {
                Err(ServiceError::Initialization(step)) => assert_eq!(step, refusal, "{key}"),
                Err(other) => panic!("{key}: {other:?}"),
                Ok(_) => panic!("{key}: fixture from refused settings"),
            }
            assert_eq!(entries(), 0, "{key} left files behind");
        }

        // The complete keys write one fixture root there, and dropping the fixture removes it.
        let fixture = FixtureFiles::write_with(base, None, &parent).expect("fixture");
        assert_eq!(entries(), 1);
        drop(fixture);
        assert_eq!(entries(), 0);
        std::fs::remove_dir(parent).expect("remove fixture parent");
        std::fs::remove_dir_all(secrets).expect("remove secrets");
    }

    #[tokio::test]
    async fn startup_reports_pending_and_mismatched_migrations() {
        let database = DatabaseFixture::new().await.expect("schema");
        let settings = &database.fixture.settings;
        let unmigrated = DocchainService::compose(settings).await.err();
        assert!(
            matches!(
                unmigrated,
                Some(ServiceError::Initialization("database migrations pending"))
            ),
            "{unmigrated:?}"
        );

        database.migrate().await.expect("migrations");
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 2")
            .bind(vec![0_u8; 48])
            .execute(&database.owner)
            .await
            .expect("tamper with the recorded checksum");
        let changed = DocchainService::compose(settings).await.err();
        assert!(
            matches!(
                changed,
                Some(ServiceError::Initialization("database migrations mismatch"))
            ),
            "{changed:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_migration_state_read_reports_database_connection() {
        let database = DatabaseFixture::new().await.expect("schema");
        database.migrate().await.expect("migrations");
        // Taken out of the pool, so any failure closes the session and releases the lock.
        let mut holder = database.owner.acquire().await.expect("holder").detach();
        sqlx::raw_sql("BEGIN; LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE")
            .execute(&mut holder)
            .await
            .expect("lock the migration ledger");

        // Only the migration-state read touches the ledger; the schema check reads a catalog.
        let startup = DocchainService::compose(&database.fixture.settings);
        tokio::pin!(startup);
        let ledger = format!("{}._sqlx_migrations", database.schema());
        let waiter = tokio::select! {
            biased;
            returned = &mut startup => {
                panic!("startup ended while the ledger was locked: {:?}", returned.err())
            }
            waiter = access_share_waiter(&database.owner, &ledger) => waiter,
        };
        // Another session of the runtime role ends the waiting read, as a lost connection
        // would.
        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(waiter)
            .fetch_one(&database.runtime)
            .await
            .expect("terminate the waiting session");
        assert!(terminated, "the runtime role ends its own role's session");
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut holder)
            .await
            .expect("release the ledger");

        let failed = tokio::time::timeout(Duration::from_secs(10), startup)
            .await
            .expect("startup returns within 10 s of the fault")
            .err();
        assert!(
            matches!(
                failed,
                Some(ServiceError::Initialization("database connection"))
            ),
            "{failed:?}"
        );
        assert_eq!(
            failed.map(|error| error.to_string()).as_deref(),
            Some("service initialization failed: database connection")
        );
    }

    /// Step 1's query, which `docchain-migrate` also runs as its schema check.
    const SCHEMA_EXISTS: &str = "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)";

    /// Sessions a [`CuttingRelay`] accepted and cut.
    #[derive(Default)]
    struct RelayCounts {
        cuts: AtomicUsize,
        accepted_after_cut: AtomicUsize,
    }

    /// A loopback TCP relay to the fixture's database server. It closes a session, without
    /// forwarding the chunk, at the first client bytes that hold one exact statement text, as a
    /// lost connection would end that query. It keeps no relayed byte beyond its match window
    /// and prints none. Dropping it ends every session it relays.
    struct CuttingRelay {
        port: u16,
        counts: Arc<RelayCounts>,
        accept: tokio::task::JoinHandle<()>,
    }

    impl CuttingRelay {
        async fn start(host: &str, port: u16, statement: &'static str) -> Self {
            assert!(!host.starts_with('/'), "the database host is a TCP host");
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("relay listener");
            let local = listener.local_addr().expect("relay address").port();
            let counts = Arc::new(RelayCounts::default());
            let upstream = (host.to_owned(), port);
            let accept = tokio::spawn({
                let counts = Arc::clone(&counts);
                async move {
                    // Aborting this task drops the set, which aborts every session.
                    let mut sessions = tokio::task::JoinSet::new();
                    while let Ok((client, _)) = listener.accept().await {
                        if counts.cuts.load(Ordering::SeqCst) > 0 {
                            counts.accepted_after_cut.fetch_add(1, Ordering::SeqCst);
                        }
                        sessions.spawn(relay_session(
                            client,
                            upstream.clone(),
                            statement,
                            Arc::clone(&counts),
                        ));
                    }
                }
            });
            Self {
                port: local,
                counts,
                accept,
            }
        }

        fn cuts(&self) -> usize {
            self.counts.cuts.load(Ordering::SeqCst)
        }

        fn accepted_after_cut(&self) -> usize {
            self.counts.accepted_after_cut.load(Ordering::SeqCst)
        }
    }

    impl Drop for CuttingRelay {
        fn drop(&mut self) {
            self.accept.abort();
        }
    }

    /// Relays one session both ways until either side closes, or until the client sends
    /// `statement`, which it drops unforwarded before closing both sockets.
    async fn relay_session(
        mut client: TcpStream,
        upstream: (String, u16),
        statement: &'static str,
        counts: Arc<RelayCounts>,
    ) {
        let Ok(mut server) = TcpStream::connect((upstream.0.as_str(), upstream.1)).await else {
            return;
        };
        let (mut client_read, mut client_write) = client.split();
        let (mut server_read, mut server_write) = server.split();
        let needle = statement.as_bytes();
        let to_server = async {
            // The previous chunk's last `needle.len() - 1` bytes, then the new chunk, so a
            // statement split across reads still matches.
            let mut window: Vec<u8> = Vec::with_capacity(needle.len() + 8192);
            let mut chunk = [0_u8; 8192];
            loop {
                let read = match client_read.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => read,
                };
                window.extend_from_slice(&chunk[..read]);
                if window
                    .windows(needle.len())
                    .any(|candidate| candidate == needle)
                {
                    counts.cuts.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if server_write.write_all(&chunk[..read]).await.is_err() {
                    return;
                }
                let keep = window.len().min(needle.len() - 1);
                window.drain(..window.len() - keep);
            }
        };
        let to_client = tokio::io::copy(&mut server_read, &mut client_write);
        tokio::select! {
            () = to_server => {}
            _ = to_client => {}
        }
    }

    #[tokio::test]
    async fn a_failed_startup_check_query_reports_database_connection() {
        let database = DatabaseFixture::new().await.expect("schema");
        database.migrate().await.expect("migrations");
        let direct = &database.fixture.settings.database;
        for (check, statement) in [
            ("schema existence", SCHEMA_EXISTS),
            ("current schema", "SELECT current_schema()::text"),
            (
                "session roles",
                "SELECT session_user::text, current_user::text",
            ),
            (
                "runtime privilege rule",
                "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)",
            ),
        ] {
            let relay = CuttingRelay::start(&direct.host, direct.port, statement).await;
            let mut settings = database.fixture.settings.clone();
            settings.database.host = "127.0.0.1".to_owned();
            settings.database.port = relay.port;

            let failed =
                tokio::time::timeout(Duration::from_secs(10), DocchainService::compose(&settings))
                    .await
                    .expect("startup returns within 10 s of the fault")
                    .err();
            assert!(
                matches!(
                    failed,
                    Some(ServiceError::Initialization("database connection"))
                ),
                "{check}: {failed:?}"
            );
            assert_eq!(
                failed.map(|error| error.to_string()).as_deref(),
                Some("service initialization failed: database connection"),
                "{check}"
            );
            assert_eq!(relay.cuts(), 1, "{check}");
            // No later check, and not the lease, opened a session after the fault.
            assert_eq!(relay.accepted_after_cut(), 0, "{check}");
            // The document store root is created only after every check passes.
            assert!(!database.fixture.object_root.exists(), "{check}");
        }
    }

    #[tokio::test]
    async fn a_failed_migrator_schema_query_reports_database_connection() {
        let database = DatabaseFixture::new().await.expect("schema");
        let direct = &database.fixture.owner;
        let relay = CuttingRelay::start(&direct.host, direct.port, SCHEMA_EXISTS).await;
        let mut owner = direct.clone();
        owner.host = "127.0.0.1".to_owned();
        owner.port = relay.port;

        let failed = tokio::time::timeout(Duration::from_secs(10), crate::migrator::run(&owner))
            .await
            .expect("migration returns within 10 s of the fault")
            .err();
        assert_eq!(
            failed.map(|step| step.to_string()).as_deref(),
            Some("database connection")
        );
        assert_eq!(relay.cuts(), 1);
        assert_eq!(relay.accepted_after_cut(), 0);
        let ledger: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(format!("{}._sqlx_migrations", database.schema()))
            .fetch_one(&database.owner)
            .await
            .expect("ledger lookup");
        assert!(!ledger, "no migration was applied");
    }

    #[tokio::test]
    async fn the_migrator_refuses_an_absent_schema() {
        let fixture = FixtureFiles::write().expect("fixture");
        let refused = tokio::time::timeout(
            Duration::from_secs(10),
            crate::migrator::run(&fixture.owner),
        )
        .await
        .expect("migration returns within 10 s")
        .err();
        assert_eq!(
            refused.map(|step| step.to_string()).as_deref(),
            Some("database schema")
        );
        assert_eq!(fixture.schema_exists().await.ok(), Some(false));
    }

    #[tokio::test]
    async fn dropping_a_harness_removes_its_schema_and_root() {
        let harness = DemoHarness::new().await.expect("harness");
        let (schema, root) = harness.fixture_location();
        let admin = harness.database.fixture.owner_options();
        assert_eq!(exists(admin.clone(), &schema).await, Some(true));
        assert!(root.exists());
        let started = Instant::now();
        drop(harness);
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(exists(admin.clone(), &schema).await, Some(false));
        assert!(!root.exists());

        // A test that panics still cleans up while it unwinds.
        let (location_tx, location_rx) = tokio::sync::oneshot::channel();
        let panicked = tokio::spawn(async move {
            let harness = DemoHarness::new().await.expect("harness");
            let _ = location_tx.send((
                harness.fixture_location(),
                harness.database.fixture.owner_options(),
            ));
            panic!("a failing test");
        })
        .await;
        assert!(panicked.is_err_and(|error| error.is_panic()));
        let ((schema, root), admin) = location_rx.await.expect("fixture location");
        assert_eq!(exists(admin, &schema).await, Some(false));
        assert!(!root.exists());
    }
}
