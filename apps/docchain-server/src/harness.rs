//! Composition of application use cases with the local adapters.

#[cfg(feature = "test-support")]
use std::sync::Arc;

use docchain_application::{
    AcceptanceResult, Actor, Adapters, Application, ApplicationError, AuditReport, Credential,
    Delivery, Limits, SendCopyCommand,
};
use docchain_domain::{Checkpoint, ExchangeId, IdempotencyKey, WalletId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use thiserror::Error;

use crate::{
    config::{DatabaseSettings, Settings},
    crypto::CryptoEngine,
    providers::{
        AuditKey, FileIdentity, FileKeyRegistry, StaticSchemaRegistry, SystemClock, load_key_files,
    },
    store::{FileDocumentStore, PgExchangeStore, migrate},
};

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
                ApplicationError::IntegrityFailure => "integrity-failure",
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

/// Fully composed local service. HTTP and test adapters call these use cases.
pub struct DocchainService {
    application: Application<ServerAdapters>,
}

impl DocchainService {
    /// Migrates the configured database schema and wires every adapter.
    pub async fn compose(settings: &Settings) -> Result<Self, ServiceError> {
        Self::compose_with_limits(settings, Limits::default()).await
    }

    async fn compose_with_limits(
        settings: &Settings,
        limits: Limits,
    ) -> Result<Self, ServiceError> {
        let database = &settings.database;
        let options = connect_options(database);
        let pool = PgPoolOptions::new()
            .max_connections(database.max_connections)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| ServiceError::Initialization("database connection"))?;
        let current_schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .map_err(|_| ServiceError::Initialization("database schema"))?;
        if current_schema != database.schema.as_str() {
            return Err(ServiceError::Initialization("database schema"));
        }
        migrate(&pool)
            .await
            .map_err(|_| ServiceError::Initialization("database migration"))?;

        let signing = load_key_files(&settings.keys.wallet_signing_private)
            .map_err(|_| ServiceError::Initialization("wallet signing key files"))?;
        let encryption = load_key_files(&settings.keys.wallet_encryption_private)
            .map_err(|_| ServiceError::Initialization("wallet encryption key files"))?;
        let adapters = ServerAdapters {
            identity: FileIdentity::load(&settings.identity_credentials_file)
                .map_err(|_| ServiceError::Initialization("identity credentials file"))?,
            schemas: StaticSchemaRegistry,
            keys: FileKeyRegistry::load(&settings.keys)
                .map_err(|_| ServiceError::Initialization("key-binding registry"))?,
            crypto: CryptoEngine::new(signing, encryption)
                .map_err(|_| ServiceError::Initialization("wallet key material"))?,
            integrity: AuditKey::load(&settings.keys.audit_private)
                .map_err(|_| ServiceError::Initialization("audit key file"))?,
            documents: FileDocumentStore::new(settings.document_store_root.clone())
                .await
                .map_err(|_| ServiceError::Initialization("document store root"))?,
            exchanges: PgExchangeStore::new(pool),
            clock: SystemClock,
        };
        Ok(Self {
            application: Application::new(adapters, limits),
        })
    }

    /// Authenticates one presented credential.
    pub async fn authenticate(&self, credential: Credential) -> Result<Actor, ServiceError> {
        self.application
            .authenticate(&credential)
            .await
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

    #[cfg(feature = "test-support")]
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        self.application.adapters().exchanges.pool()
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
    service: Arc<DocchainService>,
    fixture: FixtureFiles,
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
/// Dropping it drops the schema, if it was created, and removes the root, within five seconds,
/// also when a test panics.
#[cfg(feature = "test-support")]
pub(crate) struct FixtureFiles {
    pub(crate) schema: String,
    pub(crate) root: std::path::PathBuf,
    pub(crate) object_root: std::path::PathBuf,
    pub(crate) settings: Settings,
    /// Every `DOCCHAIN_` variable the settings came from.
    environment: Vec<(String, String)>,
    credentials: [String; 6],
}

#[cfg(feature = "test-support")]
impl FixtureFiles {
    /// Writes the fixture files under a new temporary root and builds settings naming a new,
    /// not yet created, schema.
    pub(crate) fn write() -> Result<Self, ServiceError> {
        Self::write_with(None)
    }

    /// As [`FixtureFiles::write`], appending one authority-signed revocation of the recipient's
    /// encryption key, at the next registry sequence, that takes effect at `not_before`.
    fn write_with(revocation_from: Option<&str>) -> Result<Self, ServiceError> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use serde_json::{Value, json};
        use std::{
            collections::HashMap,
            sync::atomic::{AtomicU64, Ordering},
        };

        static INSTANCE: AtomicU64 = AtomicU64::new(1);
        let suffix = INSTANCE.fetch_add(1, Ordering::Relaxed);
        let schema = format!("docchain_test_{}_{}", std::process::id(), suffix);
        let root = std::env::temp_dir().join(&schema);
        std::fs::create_dir_all(&root).map_err(|_| ServiceError::Initialization("test fixture"))?;
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
        let mut values: HashMap<String, String> = std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        values
            .entry("DOCCHAIN_DATABASE__HOST".to_owned())
            .or_insert_with(|| "postgres".to_owned());
        values
            .entry("DOCCHAIN_DATABASE__NAME".to_owned())
            .or_insert_with(|| {
                std::env::var("POSTGRES_DB").unwrap_or_else(|_| "docchain".to_owned())
            });
        values
            .entry("DOCCHAIN_DATABASE__USER".to_owned())
            .or_insert_with(|| {
                std::env::var("POSTGRES_USER").unwrap_or_else(|_| "docchain".to_owned())
            });
        if !values.contains_key("DOCCHAIN_DATABASE__PASSWORD")
            && !values.contains_key("DOCCHAIN_DATABASE__PASSWORD_FILE")
        {
            values.insert(
                "DOCCHAIN_DATABASE__PASSWORD_FILE".to_owned(),
                std::env::var("POSTGRES_PASSWORD_FILE")
                    .unwrap_or_else(|_| "/run/secrets/postgres_key".to_owned()),
            );
        }
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
                "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
                root.join("identities.json").display().to_string(),
            ),
        ] {
            values.insert(key.to_owned(), value);
        }
        let environment = values
            .iter()
            .filter(|(key, _)| key.starts_with("DOCCHAIN_"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let settings =
            Settings::from_map(values).map_err(|_| ServiceError::Initialization("test fixture"))?;

        Ok(Self {
            schema,
            root,
            object_root,
            settings,
            environment,
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

    /// Options for an administrative connection, outside any fixture schema.
    fn admin_options(&self) -> PgConnectOptions {
        connect_options(&self.settings.database)
            .application_name("docchain-test-admin")
            .options([("search_path", "public")])
    }

    /// Creates the fixture's schema.
    pub(crate) async fn create_schema(&self) -> Result<(), ServiceError> {
        use sqlx::{AssertSqlSafe, Executor as _};

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.admin_options())
            .await
            .map_err(|_| ServiceError::Initialization("test fixture"))?;
        let created = admin
            .execute(AssertSqlSafe(format!("CREATE SCHEMA {}", self.schema)))
            .await;
        admin.close().await;
        created
            .map(|_| ())
            .map_err(|_| ServiceError::Initialization("test fixture"))
    }

    /// A pool confined to the fixture's schema, as the service connects.
    #[cfg(test)]
    pub(crate) async fn pool(&self) -> Result<sqlx::PgPool, ServiceError> {
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(connect_options(&self.settings.database))
            .await
            .map_err(|_| ServiceError::Initialization("test fixture"))
    }

    /// Whether a schema with the fixture's name exists.
    #[cfg(test)]
    pub(crate) async fn schema_exists(&self) -> Result<bool, ServiceError> {
        schema_exists(self.admin_options(), &self.schema).await
    }
}

#[cfg(all(test, feature = "test-support"))]
async fn schema_exists(options: PgConnectOptions, schema: &str) -> Result<bool, ServiceError> {
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

#[cfg(feature = "test-support")]
impl Drop for FixtureFiles {
    fn drop(&mut self) {
        let options = self.admin_options();
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
                        if let Ok(admin) = PgPoolOptions::new()
                            .max_connections(1)
                            .connect_with(options)
                            .await
                        {
                            let statement = format!("DROP SCHEMA IF EXISTS {schema} CASCADE");
                            let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
                                .execute(&admin)
                                .await;
                            admin.close().await;
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
            FixtureFiles::write_with(Some("2099-01-01T00:00:00Z"))?,
            Limits::default(),
        )
        .await
    }

    async fn compose_fixture(fixture: FixtureFiles, limits: Limits) -> Result<Self, ServiceError> {
        fixture.create_schema().await?;
        let service = DocchainService::compose_with_limits(&fixture.settings, limits).await?;
        let [
            sender_credential,
            recipient_credential,
            unrelated_credential,
            unkeyed_credential,
            auditor_credential,
            operator_credential,
        ] = fixture.credentials.clone();
        Ok(Self {
            service: Arc::new(service),
            fixture,
            sender_credential,
            recipient_credential,
            unrelated_credential,
            unkeyed_credential,
            auditor_credential,
            operator_credential,
        })
    }

    /// The `DOCCHAIN_` environment that runs the server binary against this harness's own
    /// schema, document root, and key files.
    pub fn server_environment(&self) -> Vec<(String, String)> {
        self.fixture.environment.clone()
    }

    /// This harness's schema name and fixture root, for cleanup checks.
    pub fn fixture_location(&self) -> (String, std::path::PathBuf) {
        (self.fixture.schema.clone(), self.fixture.root.clone())
    }

    pub fn service(&self) -> Arc<DocchainService> {
        Arc::clone(&self.service)
    }
    pub async fn actor(&self, credential: &str) -> Result<Actor, ServiceError> {
        self.service
            .authenticate(Credential::new(credential.to_owned()))
            .await
    }
    pub async fn send_copy(
        &self,
        actor: &Actor,
        command: SendCopyCommand,
    ) -> Result<Delivery, ServiceError> {
        self.service.send_copy(actor, command).await
    }
    pub async fn accept(
        &self,
        actor: &Actor,
        exchange: &ExchangeId,
        key: &IdempotencyKey,
    ) -> Result<AcceptanceResult, ServiceError> {
        self.service.accept(actor, exchange, key).await
    }
    pub async fn read_document(
        &self,
        actor: &Actor,
        exchange: &ExchangeId,
    ) -> Result<Vec<u8>, ServiceError> {
        self.service.read_document(actor, exchange).await
    }
    pub async fn list_inbox(
        &self,
        actor: &Actor,
        wallet: &WalletId,
    ) -> Result<Vec<ExchangeId>, ServiceError> {
        self.service.list_inbox(actor, wallet).await
    }
    pub async fn verify_audit(
        &self,
        expected: Option<Checkpoint>,
    ) -> Result<AuditReport, ServiceError> {
        let actor = self.actor(&self.auditor_credential).await?;
        self.service.verify_audit(&actor, expected).await
    }
    pub async fn stats(&self) -> Result<StateStats, ServiceError> {
        let pool = self.service.pool();
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
        let mut directory = tokio::fs::read_dir(&self.fixture.object_root)
            .await
            .map_err(|_| ServiceError::Inspection)?;
        let mut objects = 0_usize;
        while directory
            .next_entry()
            .await
            .map_err(|_| ServiceError::Inspection)?
            .is_some()
        {
            objects = objects.saturating_add(1);
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
                .fetch_one(self.service.pool())
                .await
                .map_err(|_| ServiceError::Inspection)?;
        tokio::fs::read(self.fixture.object_root.join(object))
            .await
            .map_err(|_| ServiceError::Inspection)
    }
    pub async fn object_exists(&self, object: &docchain_domain::ObjectId) -> bool {
        tokio::fs::metadata(self.fixture.object_root.join(object.as_str()))
            .await
            .is_ok()
    }
    pub async fn remove_document_root(&self) -> Result<(), ServiceError> {
        tokio::fs::remove_dir_all(&self.fixture.object_root)
            .await
            .map_err(|_| ServiceError::Inspection)
    }
    pub async fn audit_events(&self) -> Result<Vec<docchain_domain::AuditEvent>, ServiceError> {
        use docchain_application::ExchangeStore as _;
        self.service
            .application
            .adapters()
            .exchanges
            .events(100_000)
            .await
            .map_err(|_| ServiceError::Inspection)
    }
    pub async fn alter_envelope(&self, exchange: &ExchangeId) -> Result<(), ServiceError> {
        let object: String =
            sqlx::query_scalar("SELECT object_id FROM exchanges WHERE exchange_id = $1")
                .bind(exchange.as_str())
                .fetch_one(self.service.pool())
                .await
                .map_err(|_| ServiceError::Inspection)?;
        let path = self.fixture.object_root.join(object);
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
            .service
            .pool()
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
    /// Runs one statement in its own transaction, optionally with
    /// `session_replication_role = replica`, and returns the rows it affected or the SQLSTATE it
    /// failed with.
    pub async fn sqlstate_of(&self, statement: &str, replica: bool) -> Result<u64, String> {
        let mut transaction = self
            .service
            .pool()
            .begin()
            .await
            .map_err(|_| "connection".to_owned())?;
        if replica {
            sqlx::raw_sql("SET LOCAL session_replication_role = replica")
                .execute(&mut *transaction)
                .await
                .map_err(|_| "replica role".to_owned())?;
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
        let pool = self.service.pool();
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
    /// Runs one statement directly against this harness's schema, bypassing every use case, so
    /// tests can tamper with stored rows the way a table writer could.
    pub async fn execute_unchecked(&self, statement: &str) -> Result<u64, ServiceError> {
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement.to_owned()))
            .execute(self.service.pool())
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
    use std::time::{Duration, Instant};

    use super::*;

    async fn exists(options: PgConnectOptions, schema: &str) -> Option<bool> {
        schema_exists(options, schema).await.ok()
    }

    #[tokio::test]
    async fn dropping_a_harness_removes_its_schema_and_root() {
        let harness = DemoHarness::new().await.expect("harness");
        let (schema, root) = harness.fixture_location();
        let admin = harness.fixture.admin_options();
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
            let _ = location_tx.send((harness.fixture_location(), harness.fixture.admin_options()));
            panic!("a failing test");
        })
        .await;
        assert!(panicked.is_err_and(|error| error.is_panic()));
        let ((schema, root), admin) = location_rx.await.expect("fixture location");
        assert_eq!(exists(admin, &schema).await, Some(false));
        assert!(!root.exists());
    }
}
