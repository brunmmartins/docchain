//! Closed-schema operational diagnostics: request and use-case span records, startup-failure
//! records, and the operation × outcome counters.
//!
//! Every record is one JSON object per line on standard output. Each record field is a field-less
//! enum or an integer, so no request data, identifier, path, key, secret, or free text can reach a
//! record by any path. Requests never block or wait on diagnostics: a record goes through a bounded
//! queue to one writer thread. A full or closed queue drops the record and counts the drop, and so
//! does a write that standard output refuses in whole or in part. A refused record is never
//! retried.
//!
//! Records are best-effort activity metadata, not an audit trail. The counters and the
//! dropped-record count are updated directly, never through the queue, so they stay exact.
//! Records still queued when the exit flush ends are lost without being counted.

use std::{
    future::Future,
    io::Write,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use axum::{
    extract::{FromRequestParts, MatchedPath, Request, State},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};
use docchain_application::{ApplicationError, OperationalReadGrant};
use serde::{Serialize, Serializer};

use crate::{
    ServiceError,
    http::{
        ACCEPT_ROUTE, AUDIT_EXPORT_ROUTE, AUDIT_KEY_ROUTE, AUDIT_VERIFY_ROUTE, COUNTERS_ROUTE,
        INBOX_ROUTE, LIVE_ROUTE, READ_DOCUMENT_ROUTE, READY_ROUTE, SEND_COPIES_ROUTE,
    },
};

/// Most records waiting for the writer; a record that finds the queue full is dropped.
pub const QUEUE_CAPACITY: usize = 4_096;

/// Longest the process waits at exit for queued records to be written.
pub const EXIT_FLUSH_LIMIT: Duration = Duration::from_secs(1);

/// Most records the writer takes before flushing, so a busy queue still reports progress.
const WRITE_BATCH: u64 = 256;

/// Defines a field-less enum whose wire texts are the literals listed here, with its value list,
/// a serializer that writes only the wire text, and, after `lookup`, an exact-match lookup.
macro_rules! closed_enum {
    (
        lookup
        $(#[$meta:meta])*
        $name:ident { $($(#[$variant_meta:meta])* $variant:ident => $text:literal,)+ }
    ) => {
        closed_enum! {
            $(#[$meta])*
            $name { $($(#[$variant_meta])* $variant => $text,)+ }
        }

        impl $name {
            /// The value whose wire text equals `text` exactly.
            fn exact(text: &str) -> Option<Self> {
                match text {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$variant_meta:meta])* $variant:ident => $text:literal,)+ }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* #[doc = concat!("`", $text, "`")] $variant,)+
        }

        impl $name {
            /// How many values exist.
            pub const COUNT: usize = [$($text),+].len();
            /// Every value, in declaration order.
            pub const ALL: [Self; Self::COUNT] = [$(Self::$variant),+];

            /// The value's wire text.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

closed_enum! {
    /// The operation a request addressed, from its matched route template only.
    Operation {
        SendCopy => "send-copy",
        Accept => "accept",
        ReadDocument => "read-document",
        ListInbox => "list-inbox",
        VerifyAudit => "verify-audit",
        AuditKey => "audit-key",
        ExportAuditEvents => "export-audit-events",
        Live => "live",
        Ready => "ready",
        ReadCounters => "read-counters",
        Unmatched => "unmatched",
    }
}

impl Operation {
    /// The operation whose route constant equals `template` exactly; no template, or any other
    /// text, is `unmatched`.
    #[must_use]
    pub fn from_route(template: Option<&str>) -> Self {
        match template {
            Some(SEND_COPIES_ROUTE) => Self::SendCopy,
            Some(ACCEPT_ROUTE) => Self::Accept,
            Some(READ_DOCUMENT_ROUTE) => Self::ReadDocument,
            Some(INBOX_ROUTE) => Self::ListInbox,
            Some(AUDIT_VERIFY_ROUTE) => Self::VerifyAudit,
            Some(AUDIT_KEY_ROUTE) => Self::AuditKey,
            Some(AUDIT_EXPORT_ROUTE) => Self::ExportAuditEvents,
            Some(LIVE_ROUTE) => Self::Live,
            Some(READY_ROUTE) => Self::Ready,
            Some(COUNTERS_ROUTE) => Self::ReadCounters,
            _ => Self::Unmatched,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

closed_enum! {
    /// How a request or use case ended, from a typed error, a readiness result, or a status class.
    Outcome {
        Ok => "ok",
        NotReady => "not-ready",
        Unauthenticated => "unauthenticated",
        Forbidden => "forbidden",
        InvalidRequest => "invalid-request",
        InvalidDocument => "invalid-document",
        UnsupportedSchema => "unsupported-schema",
        KeyBinding => "key-binding",
        Replay => "replay",
        PendingLimit => "pending-limit",
        InvalidEnvelope => "invalid-envelope",
        IntegrityFailure => "integrity-failure",
        AuditIncomplete => "audit-incomplete",
        DependencyFailure => "dependency-failure",
        Overloaded => "overloaded",
        Timeout => "timeout",
        NotFound => "not-found",
        MethodNotAllowed => "method-not-allowed",
        PayloadTooLarge => "payload-too-large",
        Rejected => "rejected",
        ServerError => "server-error",
        Cancelled => "cancelled",
    }
}

impl Outcome {
    /// The outcome of a typed service error, matching its response category.
    #[must_use]
    pub const fn from_service_error(error: &ServiceError) -> Self {
        match error {
            ServiceError::Application(error) => match error {
                ApplicationError::Unauthenticated => Self::Unauthenticated,
                ApplicationError::Forbidden => Self::Forbidden,
                ApplicationError::InvalidRequest => Self::InvalidRequest,
                ApplicationError::InvalidDocument => Self::InvalidDocument,
                ApplicationError::UnsupportedSchema => Self::UnsupportedSchema,
                ApplicationError::KeyBinding => Self::KeyBinding,
                ApplicationError::Replay => Self::Replay,
                ApplicationError::PendingLimit => Self::PendingLimit,
                ApplicationError::InvalidEnvelope => Self::InvalidEnvelope,
                ApplicationError::IntegrityFailure | ApplicationError::AuditMismatch(_) => {
                    Self::IntegrityFailure
                }
                ApplicationError::AuditIncomplete => Self::AuditIncomplete,
                ApplicationError::Unavailable | ApplicationError::Invariant => {
                    Self::DependencyFailure
                }
            },
            ServiceError::Initialization(_) => Self::DependencyFailure,
            #[cfg(feature = "test-support")]
            ServiceError::Inspection => Self::DependencyFailure,
        }
    }

    /// The outcome of a use-case result.
    #[must_use]
    pub const fn of<T>(result: &Result<T, ServiceError>) -> Self {
        match result {
            Ok(_) => Self::Ok,
            Err(error) => Self::from_service_error(error),
        }
    }

    /// The outcome of a response that carries no typed outcome, from its status alone.
    #[must_use]
    pub fn from_status(status: StatusCode) -> Self {
        match status {
            status if status.is_success() => Self::Ok,
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => Self::MethodNotAllowed,
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge,
            status if status.is_server_error() => Self::ServerError,
            _ => Self::Rejected,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

closed_enum! {
    lookup
    /// The startup step that failed before the listener bound.
    StartupStep {
        Configuration => "configuration",
        DatabaseConnection => "database connection",
        DatabaseSchema => "database schema",
        DatabaseMigrationsMismatch => "database migrations mismatch",
        DatabaseMigrationsPending => "database migrations pending",
        DatabaseRolePrivileges => "database role privileges",
        WalletSigningKeyFiles => "wallet signing key files",
        WalletEncryptionKeyFiles => "wallet encryption key files",
        AuditKeyFile => "audit key file",
        AuditPublicKey => "audit public key",
        AuditPublicKeyFingerprint => "audit public key fingerprint",
        AuditSettings => "audit settings",
        IdentityCredentialsFile => "identity credentials file",
        KeyBindingRegistry => "key-binding registry",
        WalletKeyMaterial => "wallet key material",
        DocumentStoreRoot => "document store root",
        DocumentStoreExclusivity => "document store exclusivity",
        DocumentStoreBinding => "document store binding",
        DocumentStoreInventory => "document store inventory",
        DocumentStoreReferences => "document store references",
        DocumentStoreSweep => "document store sweep",
        SignalListener => "signal listener",
        HttpListener => "HTTP listener",
        ServiceInitialization => "service initialization",
    }
}

impl StartupStep {
    /// The step whose text equals `step` exactly, else `service initialization`. Nothing about
    /// `step` is kept.
    #[must_use]
    pub fn new(step: &str) -> Self {
        Self::exact(step).unwrap_or(Self::ServiceInitialization)
    }
}

closed_enum! {
    lookup
    /// The configuration key that failed.
    Setting {
        DatabaseHost => "DOCCHAIN_DATABASE__HOST",
        DatabasePort => "DOCCHAIN_DATABASE__PORT",
        DatabaseName => "DOCCHAIN_DATABASE__NAME",
        DatabaseSchema => "DOCCHAIN_DATABASE__SCHEMA",
        DatabaseUser => "DOCCHAIN_DATABASE__USER",
        DatabasePassword => "DOCCHAIN_DATABASE__PASSWORD",
        DatabasePasswordFile => "DOCCHAIN_DATABASE__PASSWORD_FILE",
        DatabaseMaxConnections => "DOCCHAIN_DATABASE__MAX_CONNECTIONS",
        HttpBind => "DOCCHAIN_HTTP__BIND",
        HttpRequestTimeout => "DOCCHAIN_HTTP__REQUEST_TIMEOUT_MS",
        HttpMaxInFlight => "DOCCHAIN_HTTP__MAX_IN_FLIGHT",
        HttpShutdownTimeout => "DOCCHAIN_HTTP__SHUTDOWN_TIMEOUT_MS",
        DocumentStoreRoot => "DOCCHAIN_DOCUMENT_STORE__ROOT",
        RegistryAuthorityPublicKeyFile => "DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE",
        BindingsFile => "DOCCHAIN_KEYS__BINDINGS_FILE",
        WalletSigningPrivateKeyFiles => "DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES",
        WalletEncryptionPrivateKeyFiles => "DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES",
        AuditPrivateKeyFile => "DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE",
        AuditPublicKeyFingerprint => "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT",
        AuditMaxExportEvents => "DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS",
        AuditDefaultPageSize => "DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE",
        IdentityCredentialsFile => "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
        DiagnosticsSpans => "DOCCHAIN_DIAGNOSTICS__SPANS",
        PgOptions => "PGOPTIONS",
        AnyMigration => "DOCCHAIN_MIGRATION__*",
        Any => "DOCCHAIN_*",
    }
}

impl Setting {
    /// The setting whose key equals `key` exactly; any other migration key is
    /// `DOCCHAIN_MIGRATION__*`, and any other key is `DOCCHAIN_*`. Nothing about `key` is kept.
    #[must_use]
    pub fn new(key: &str) -> Self {
        Self::exact(key).unwrap_or(if key.starts_with("DOCCHAIN_MIGRATION__") {
            Self::AnyMigration
        } else {
            Self::Any
        })
    }
}

closed_enum! {
    lookup
    /// Why a configuration key failed.
    SettingReason {
        Required => "is required",
        NotIdentifier => "must be a lower-case PostgreSQL identifier",
        PublicSchema => "must not be public; use a schema the migration owner owns",
        SameAsOwner => "must differ from DOCCHAIN_MIGRATION__USER",
        MigrationKeyForServer => "must not be set for the server; only docchain-migrate reads it",
        Empty => "must not be empty",
        ConnectionsRange => "must be from 2 through 64",
        NotSocketAddress => "must be a socket address",
        InFlightRange => "must be from 1 through 1024",
        NotAbsolute => "must be an absolute non-root path",
        ExportEventsRange => "must be from 1 through 100000",
        PageSizeRange => "must be from 1 through 500",
        PgOptionsSet => "must not be set; use DOCCHAIN_DATABASE__SCHEMA",
        NameNotUnicode => "name is not Unicode",
        ValueNotUnicode => "value is not Unicode",
        UnreadableSecretFile => "cannot read secret file",
        EmptySecretFile => "secret file is empty",
        NotBase64Url => "must be canonical unpadded base64url",
        Not32Bytes => "must encode exactly 32 bytes",
        InvalidValue => "has an invalid value",
        MillisRange => "must be from 1 through 60000",
        NoPath => "requires at least one path",
        NotOnOrOff => "must be on or off",
        Invalid => "is invalid",
    }
}

impl SettingReason {
    /// The reason whose text equals `reason` exactly, else `is invalid`. Nothing about `reason`
    /// is kept.
    #[must_use]
    pub fn new(reason: &str) -> Self {
        Self::exact(reason).unwrap_or(Self::Invalid)
    }
}

/// One startup failure: the step, plus the setting and reason when the step is `configuration`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StartupFailure {
    step: StartupStep,
    #[serde(skip_serializing_if = "Option::is_none")]
    setting: Option<Setting>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<SettingReason>,
}

impl StartupFailure {
    /// A failure at `step`. A `configuration` step built here names the fallback setting and
    /// reason; use [`StartupFailure::configuration`] to name them.
    #[must_use]
    pub const fn at(step: StartupStep) -> Self {
        match step {
            StartupStep::Configuration => Self::configuration(Setting::Any, SettingReason::Invalid),
            step => Self {
                step,
                setting: None,
                reason: None,
            },
        }
    }

    /// A configuration failure naming the setting and why it failed.
    #[must_use]
    pub const fn configuration(setting: Setting, reason: SettingReason) -> Self {
        Self {
            step: StartupStep::Configuration,
            setting: Some(setting),
            reason: Some(reason),
        }
    }
}

/// The fields a request or use-case record holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct Span {
    request_id: u64,
    operation: Operation,
    outcome: Outcome,
    duration_us: u64,
}

/// Every record the server writes. The tag is the `record` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "record", rename_all = "kebab-case")]
enum Record {
    Request(Span),
    UseCase(Span),
    StartupFailed(StartupFailure),
}

/// The fixed operation × outcome matrix, and the count of dropped records.
pub struct Counters {
    cells: [[AtomicU64; Outcome::COUNT]; Operation::COUNT],
    dropped_records: AtomicU64,
}

impl Counters {
    fn new() -> Self {
        Self {
            cells: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            dropped_records: AtomicU64::new(0),
        }
    }

    fn cell(&self, operation: Operation, outcome: Outcome) -> &AtomicU64 {
        // Both indexes are enum discriminants, so each is below its dimension.
        &self.cells[operation.index()][outcome.index()]
    }

    fn increment(&self, operation: Operation, outcome: Outcome) {
        self.cell(operation, outcome)
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_drop(&self) {
        self.dropped_records.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads every nonzero cell, in declaration order of operation then outcome, and the
    /// dropped-record count. Only an operator the application authorized holds a grant.
    ///
    /// Each cell is exact, but the snapshot is not atomic across cells.
    #[must_use]
    pub fn snapshot(&self, _grant: &OperationalReadGrant) -> CountersSnapshot {
        self.read()
    }

    fn read(&self) -> CountersSnapshot {
        let mut counters = Vec::new();
        for operation in Operation::ALL {
            for outcome in Outcome::ALL {
                let count = self.cell(operation, outcome).load(Ordering::Relaxed);
                if count > 0 {
                    counters.push(CounterEntry {
                        operation,
                        outcome,
                        count,
                    });
                }
            }
        }
        CountersSnapshot {
            version: 1,
            counters,
            dropped_records: self.dropped_records.load(Ordering::Relaxed),
        }
    }
}

/// The counters document: version, nonzero cells, and dropped records. It holds no identifier,
/// timestamp, or free text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CountersSnapshot {
    version: u32,
    counters: Vec<CounterEntry>,
    dropped_records: u64,
}

/// One nonzero counter cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct CounterEntry {
    operation: Operation,
    outcome: Outcome,
    count: u64,
}

/// Where records go.
enum Output {
    /// The writer thread's queue. A full or disconnected queue drops the record and counts it,
    /// and the writer counts every record its output refuses in whole or in part.
    Queue(SyncSender<Record>),
    /// Nowhere, and nothing is counted as dropped: the handle writes no records at all.
    Discard,
}

/// How many records were queued, and how many of them the writer settled: written in full, or
/// lost because the output refused them in whole or in part. The exit flush waits on it.
#[derive(Default)]
struct Progress {
    queued: AtomicU64,
    settled: Mutex<Settled>,
    advanced: Condvar,
}

/// Records the writer has taken from the queue, by result. Both counts only grow.
#[derive(Clone, Copy, Default)]
struct Settled {
    written: u64,
    lost: u64,
}

impl Settled {
    fn total(self) -> u64 {
        self.written.saturating_add(self.lost)
    }
}

impl Progress {
    /// Adds a batch's results. The writer counts each lost record as dropped before calling this,
    /// so a flush that returns has seen every count for the records it waited on.
    fn advance(&self, written: u64, lost: u64) {
        let mut settled = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        settled.written = settled.written.saturating_add(written);
        settled.lost = settled.lost.saturating_add(lost);
        self.advanced.notify_all();
    }

    /// Waits until every record queued so far is settled, or `limit` passes. Returns whether
    /// every one of them was written in full and no record was ever lost by the output.
    fn wait(&self, limit: Duration) -> bool {
        let target = self.queued.load(Ordering::Acquire);
        let settled = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        let (settled, _) = self
            .advanced
            .wait_timeout_while(settled, limit, |settled| settled.total() < target)
            .unwrap_or_else(PoisonError::into_inner);
        settled.lost == 0 && settled.written >= target
    }
}

struct Shared {
    output: Output,
    counters: Arc<Counters>,
    next_request_id: AtomicU64,
    progress: Arc<Progress>,
}

/// A handle to the process's diagnostics: its record output, counters, and request IDs.
///
/// Cloning is cheap, and every clone shares the same output and counters.
#[derive(Clone)]
pub struct Diagnostics {
    shared: Arc<Shared>,
    spans: bool,
}

impl Diagnostics {
    /// Starts the `docchain-diagnostics` writer thread, which writes records to standard output.
    ///
    /// Span records are on until [`Diagnostics::with_spans`] turns them off. When the thread
    /// cannot start, every record is dropped and counted, and the handle still works. A record
    /// that standard output refuses in whole or in part is dropped and counted too, and is never
    /// retried.
    #[must_use]
    pub fn start() -> Self {
        Self::spawn(QUEUE_CAPACITY, std::io::stdout())
    }

    /// A handle that writes no record. Counters still count.
    #[must_use]
    pub fn discarding() -> Self {
        Self::with_output(Output::Discard, Arc::default(), Arc::new(Counters::new()))
    }

    /// A handle that writes records to a buffer, for tests. Records are written through the
    /// same bounded queue and writer thread as in production.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn capture() -> (Self, Captured) {
        let buffer = SharedBuffer::default();
        let diagnostics = Self::spawn(QUEUE_CAPACITY, buffer.clone());
        let captured = Captured {
            buffer,
            diagnostics: diagnostics.clone(),
        };
        (diagnostics, captured)
    }

    fn spawn<W: Write + Send + 'static>(capacity: usize, output: W) -> Self {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let progress = Arc::<Progress>::default();
        let counters = Arc::new(Counters::new());
        // The writer holds neither the sender nor `Shared`, so it ends once every handle is gone.
        let writer_progress = Arc::clone(&progress);
        let writer_counters = Arc::clone(&counters);
        // A failed spawn drops the receiver, so every later record is dropped and counted.
        let _detached = thread::Builder::new()
            .name("docchain-diagnostics".to_owned())
            .spawn(move || write_records(&receiver, output, &writer_progress, &writer_counters));
        Self::with_output(Output::Queue(sender), progress, counters)
    }

    fn with_output(output: Output, progress: Arc<Progress>, counters: Arc<Counters>) -> Self {
        Self {
            shared: Arc::new(Shared {
                output,
                counters,
                next_request_id: AtomicU64::new(1),
                progress,
            }),
            spans: true,
        }
    }

    /// This handle with span records switched on or off. Counters and startup-failure records
    /// are always on.
    #[must_use]
    pub fn with_spans(mut self, spans: bool) -> Self {
        self.spans = spans;
        self
    }

    /// The counters, readable only with an application grant.
    #[must_use]
    pub fn counters(&self) -> &Counters {
        &self.shared.counters
    }

    /// Writes one startup-failure record.
    pub fn startup_failed(&self, failure: StartupFailure) {
        self.emit(Record::StartupFailed(failure));
    }

    /// Waits until the writer has settled every record queued so far, or `limit` passes.
    /// Returns `true` only when every one of them was written in full, and no record was ever
    /// refused by the output: once a write is refused, every later flush returns `false`.
    ///
    /// # Blocking
    ///
    /// Blocks the calling thread for at most `limit`; call it at exit, never in a request.
    pub fn flush(&self, limit: Duration) -> bool {
        match self.shared.output {
            Output::Queue(_) => self.shared.progress.wait(limit),
            Output::Discard => true,
        }
    }

    /// Queues `record` without blocking; a full or closed queue drops and counts it.
    fn emit(&self, record: Record) {
        let Output::Queue(sender) = &self.shared.output else {
            return;
        };
        match sender.try_send(record) {
            Ok(()) => {
                self.shared.progress.queued.fetch_add(1, Ordering::Release);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.shared.counters.record_drop();
            }
        }
    }

    fn open_request(&self, operation: Operation) -> RequestSpan {
        RequestSpan {
            scope: UseCaseScope {
                diagnostics: self.clone(),
                request_id: self.shared.next_request_id.fetch_add(1, Ordering::Relaxed),
                operation,
            },
            started: Instant::now(),
            closed: false,
        }
    }
}

/// Serializes each queued record as one line until every sender is gone.
///
/// A record the output refuses, in whole or in part, is lost: it is counted as dropped and never
/// retried, and no repair bytes follow a partial line. The operation × outcome cells are not
/// touched here.
fn write_records<W: Write>(
    receiver: &Receiver<Record>,
    mut output: W,
    progress: &Progress,
    counters: &Counters,
) {
    while let Ok(record) = receiver.recv() {
        let mut batch = Batch::default();
        batch.settle(write_line(&mut output, &record), counters);
        while batch.taken() < WRITE_BATCH {
            let Ok(record) = receiver.try_recv() else {
                break;
            };
            batch.settle(write_line(&mut output, &record), counters);
        }
        // Each record's `write_all` already reached the descriptor, because a line ending in a
        // newline is never held in standard output's buffer, so this result reports nothing new.
        let _ = output.flush();
        progress.advance(batch.written, batch.lost);
    }
}

/// One batch's results, before they are published to the exit flush.
#[derive(Default)]
struct Batch {
    written: u64,
    lost: u64,
}

impl Batch {
    fn taken(&self) -> u64 {
        self.written.saturating_add(self.lost)
    }

    /// Counts a lost record as dropped at once, so the count precedes the batch's progress.
    fn settle(&mut self, written: bool, counters: &Counters) {
        if written {
            self.written = self.written.saturating_add(1);
        } else {
            counters.record_drop();
            self.lost = self.lost.saturating_add(1);
        }
    }
}

/// Writes `record` as one line, and returns whether the whole line was written.
#[must_use]
fn write_line<W: Write>(output: &mut W, record: &Record) -> bool {
    // The record types serialize infallibly: field-less enums, integers, and a tag. A failure
    // would still lose the record, so it counts as one.
    let Ok(mut line) = serde_json::to_vec(record) else {
        return false;
    };
    line.push(b'\n');
    output.write_all(&line).is_ok()
}

/// Microseconds since `started`, saturating.
fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// The request's open span. Closing it, or dropping it unclosed as `cancelled`, records it once.
struct RequestSpan {
    scope: UseCaseScope,
    started: Instant,
    closed: bool,
}

impl RequestSpan {
    fn close(mut self, outcome: Outcome) {
        self.finish(outcome);
    }

    fn finish(&mut self, outcome: Outcome) {
        if self.closed {
            return;
        }
        self.closed = true;
        let diagnostics = &self.scope.diagnostics;
        diagnostics
            .counters()
            .increment(self.scope.operation, outcome);
        if diagnostics.spans {
            diagnostics.emit(Record::Request(Span {
                request_id: self.scope.request_id,
                operation: self.scope.operation,
                outcome,
                duration_us: elapsed_us(self.started),
            }));
        }
    }
}

impl Drop for RequestSpan {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}

/// The request's ID and operation, which its use-case span repeats.
#[derive(Clone)]
pub(crate) struct UseCaseScope {
    diagnostics: Diagnostics,
    request_id: u64,
    operation: Operation,
}

impl UseCaseScope {
    /// Runs one application call inside a use-case span.
    pub(crate) async fn run<T>(
        &self,
        call: impl Future<Output = Result<T, ServiceError>>,
    ) -> Result<T, ServiceError> {
        let mut span = UseCaseSpan::open(self);
        let result = call.await;
        span.finish(Outcome::of(&result));
        result
    }

    /// Runs one synchronous application call inside a use-case span.
    pub(crate) fn run_sync<T>(
        &self,
        call: impl FnOnce() -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let mut span = UseCaseSpan::open(self);
        let result = call();
        span.finish(Outcome::of(&result));
        result
    }
}

impl<S: Send + Sync> FromRequestParts<S> for UseCaseScope {
    type Rejection = std::convert::Infallible;

    /// The scope the request-span middleware stored; without one, a scope that records nothing.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<Self>()
            .cloned()
            .unwrap_or_else(|| Self {
                diagnostics: Diagnostics::discarding(),
                request_id: 0,
                operation: Operation::Unmatched,
            }))
    }
}

/// An open use-case span. Finishing it, or dropping it unfinished as `cancelled`, records it once.
struct UseCaseSpan<'a> {
    scope: &'a UseCaseScope,
    started: Instant,
    closed: bool,
}

impl<'a> UseCaseSpan<'a> {
    fn open(scope: &'a UseCaseScope) -> Self {
        Self {
            scope,
            started: Instant::now(),
            closed: false,
        }
    }

    fn finish(&mut self, outcome: Outcome) {
        if self.closed {
            return;
        }
        self.closed = true;
        let diagnostics = &self.scope.diagnostics;
        if diagnostics.spans {
            diagnostics.emit(Record::UseCase(Span {
                request_id: self.scope.request_id,
                operation: self.scope.operation,
                outcome,
                duration_us: elapsed_us(self.started),
            }));
        }
    }
}

impl Drop for UseCaseSpan<'_> {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}

/// Opens one request span around every routed request, including the fallback.
///
/// The operation comes from the matched route template only; the outcome comes from the
/// response's typed outcome, else its status. No part of the request is read or kept, and client
/// correlation headers are ignored.
pub(crate) async fn request_span(
    State(diagnostics): State<Diagnostics>,
    mut request: Request,
    next: Next,
) -> Response {
    let operation = Operation::from_route(
        request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let span = diagnostics.open_request(operation);
    request.extensions_mut().insert(span.scope.clone());
    let response = next.run(request).await;
    let outcome = response
        .extensions()
        .get::<Outcome>()
        .copied()
        .unwrap_or_else(|| Outcome::from_status(response.status()));
    span.close(outcome);
    response
}

/// A writer into shared memory, for captured records.
#[cfg(feature = "test-support")]
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

#[cfg(feature = "test-support")]
impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Records a [`Diagnostics::capture`] handle wrote.
#[cfg(feature = "test-support")]
pub struct Captured {
    buffer: SharedBuffer,
    diagnostics: Diagnostics,
}

#[cfg(feature = "test-support")]
impl Captured {
    /// Every line written so far, after waiting up to five seconds for queued records.
    ///
    /// # Panics
    ///
    /// When queued records are still unwritten after five seconds, or a line is not UTF-8.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        assert!(
            self.diagnostics.flush(Duration::from_secs(5)),
            "captured diagnostics flush"
        );
        let bytes = self
            .buffer
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes)
            .expect("records are UTF-8 JSON")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Discards every line written so far, after waiting for queued records.
    pub fn clear(&self) {
        let _ = self.lines();
        self.buffer
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

#[cfg(test)]
mod tests;
