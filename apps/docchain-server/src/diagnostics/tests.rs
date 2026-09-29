use std::collections::BTreeSet;

use docchain_application::AuditMismatch;
use serde_json::Value;

use super::*;

/// A writer into memory, for records written by a real writer thread.
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Vec<u8>>>);

impl Write for Memory {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("memory").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Memory {
    fn lines(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().expect("memory").clone())
            .expect("UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
            .collect()
    }
}

fn recording() -> (Diagnostics, Memory) {
    let memory = Memory::default();
    (Diagnostics::spawn(QUEUE_CAPACITY, memory.clone()), memory)
}

/// A handle whose queue holds `capacity` records and is never drained while `_receiver` lives.
fn stalled(capacity: usize) -> (Diagnostics, Receiver<Record>) {
    let (sender, receiver) = mpsc::sync_channel(capacity);
    (
        Diagnostics::with_output(Output::Queue(sender), Arc::default()),
        receiver,
    )
}

/// Every nonzero cell, as `(operation, outcome, count)`.
fn cells(diagnostics: &Diagnostics) -> Vec<(Operation, Outcome, u64)> {
    diagnostics
        .counters()
        .read()
        .counters
        .iter()
        .map(|entry| (entry.operation, entry.outcome, entry.count))
        .collect()
}

fn dropped(diagnostics: &Diagnostics) -> u64 {
    diagnostics.counters().read().dropped_records
}

fn keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect()
}

fn application_errors() -> Vec<ApplicationError> {
    vec![
        ApplicationError::Unauthenticated,
        ApplicationError::Forbidden,
        ApplicationError::InvalidRequest,
        ApplicationError::InvalidDocument,
        ApplicationError::UnsupportedSchema,
        ApplicationError::KeyBinding,
        ApplicationError::Replay,
        ApplicationError::PendingLimit,
        ApplicationError::InvalidEnvelope,
        ApplicationError::IntegrityFailure,
        ApplicationError::AuditMismatch(AuditMismatch::EventChain),
        ApplicationError::AuditIncomplete,
        ApplicationError::Unavailable,
        ApplicationError::Invariant,
    ]
}

#[test]
fn dimensions_are_fixed_and_their_wire_texts_distinct() {
    assert_eq!((Operation::COUNT, Outcome::COUNT), (11, 22));
    for texts in [
        Operation::ALL.map(Operation::as_str).to_vec(),
        Outcome::ALL.map(Outcome::as_str).to_vec(),
        StartupStep::ALL.map(StartupStep::as_str).to_vec(),
        Setting::ALL.map(Setting::as_str).to_vec(),
        SettingReason::ALL.map(SettingReason::as_str).to_vec(),
    ] {
        assert_eq!(texts.iter().collect::<BTreeSet<_>>().len(), texts.len());
    }
    for (index, operation) in Operation::ALL.into_iter().enumerate() {
        assert_eq!(operation.index(), index);
    }
    for (index, outcome) in Outcome::ALL.into_iter().enumerate() {
        assert_eq!(outcome.index(), index);
    }
}

#[test]
fn every_service_error_maps_to_the_outcome_named_by_its_category() {
    let mut errors: Vec<ServiceError> = application_errors()
        .into_iter()
        .map(ServiceError::Application)
        .collect();
    errors.push(ServiceError::Initialization("database connection"));
    for error in &errors {
        assert_eq!(
            Outcome::from_service_error(error).as_str(),
            error.category(),
            "{error:?}"
        );
    }
    assert_eq!(
        Outcome::from_service_error(&ServiceError::Application(ApplicationError::AuditMismatch(
            AuditMismatch::CreditMissing
        ))),
        Outcome::IntegrityFailure
    );
    assert_eq!(Outcome::of::<()>(&Ok(())), Outcome::Ok);
    assert_eq!(
        Outcome::of::<()>(&Err(ServiceError::Application(ApplicationError::Invariant))),
        Outcome::DependencyFailure
    );
}

#[test]
fn a_status_without_a_typed_outcome_maps_by_class() {
    for (status, outcome) in [
        (StatusCode::OK, Outcome::Ok),
        (StatusCode::CREATED, Outcome::Ok),
        (StatusCode::NO_CONTENT, Outcome::Ok),
        (StatusCode::NOT_FOUND, Outcome::NotFound),
        (StatusCode::METHOD_NOT_ALLOWED, Outcome::MethodNotAllowed),
        (StatusCode::PAYLOAD_TOO_LARGE, Outcome::PayloadTooLarge),
        (StatusCode::BAD_REQUEST, Outcome::Rejected),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, Outcome::Rejected),
        (StatusCode::MOVED_PERMANENTLY, Outcome::Rejected),
        (StatusCode::INTERNAL_SERVER_ERROR, Outcome::ServerError),
        (StatusCode::SERVICE_UNAVAILABLE, Outcome::ServerError),
    ] {
        assert_eq!(Outcome::from_status(status), outcome, "{status}");
    }
}

#[test]
fn every_route_constant_names_its_own_operation() {
    let routes = [
        (SEND_COPIES_ROUTE, Operation::SendCopy),
        (ACCEPT_ROUTE, Operation::Accept),
        (READ_DOCUMENT_ROUTE, Operation::ReadDocument),
        (INBOX_ROUTE, Operation::ListInbox),
        (AUDIT_VERIFY_ROUTE, Operation::VerifyAudit),
        (AUDIT_KEY_ROUTE, Operation::AuditKey),
        (AUDIT_EXPORT_ROUTE, Operation::ExportAuditEvents),
        (LIVE_ROUTE, Operation::Live),
        (READY_ROUTE, Operation::Ready),
        (COUNTERS_ROUTE, Operation::ReadCounters),
    ];
    for (route, operation) in routes {
        assert_eq!(Operation::from_route(Some(route)), operation, "{route}");
    }
    assert_eq!(
        routes
            .iter()
            .map(|(_, operation)| *operation)
            .chain([Operation::Unmatched])
            .map(Operation::as_str)
            .collect::<BTreeSet<_>>()
            .len(),
        Operation::COUNT
    );
    // A raw path, a near miss, and no template are all unmatched.
    for template in [
        None,
        Some("/v1/exchanges/exc_00000000000000000000000000000000/document"),
        Some("/v1/send-copies/"),
        Some(""),
    ] {
        assert_eq!(Operation::from_route(template), Operation::Unmatched);
    }
}

#[test]
fn startup_steps_map_every_production_text_and_fail_safe() {
    for step in [
        "database connection",
        "database schema",
        "database migrations mismatch",
        "database migrations pending",
        "database role privileges",
        "wallet signing key files",
        "wallet encryption key files",
        "audit key file",
        "audit public key",
        "audit public key fingerprint",
        "audit settings",
        "identity credentials file",
        "key-binding registry",
        "wallet key material",
        "document store root",
        "document store exclusivity",
        "document store binding",
        "document store inventory",
        "document store references",
        "document store sweep",
        "configuration",
        "signal listener",
        "HTTP listener",
    ] {
        let mapped = StartupStep::new(step);
        assert_eq!(mapped.as_str(), step);
        assert_ne!(mapped, StartupStep::ServiceInitialization, "{step}");
    }
    let runtime = format!("{}{}", "document store root ", "/private/root");
    for text in [
        runtime.as_str(),
        "test fixture",
        "Database connection",
        "database connection ",
        "",
    ] {
        assert_eq!(StartupStep::new(text), StartupStep::ServiceInitialization);
    }
}

#[test]
fn settings_map_every_key_and_fail_safe() {
    let keys = [
        "DOCCHAIN_DATABASE__HOST",
        "DOCCHAIN_DATABASE__PORT",
        "DOCCHAIN_DATABASE__NAME",
        "DOCCHAIN_DATABASE__SCHEMA",
        "DOCCHAIN_DATABASE__USER",
        "DOCCHAIN_DATABASE__PASSWORD",
        "DOCCHAIN_DATABASE__PASSWORD_FILE",
        "DOCCHAIN_DATABASE__MAX_CONNECTIONS",
        "DOCCHAIN_HTTP__BIND",
        "DOCCHAIN_HTTP__REQUEST_TIMEOUT_MS",
        "DOCCHAIN_HTTP__MAX_IN_FLIGHT",
        "DOCCHAIN_HTTP__SHUTDOWN_TIMEOUT_MS",
        "DOCCHAIN_DOCUMENT_STORE__ROOT",
        "DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE",
        "DOCCHAIN_KEYS__BINDINGS_FILE",
        "DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES",
        "DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES",
        "DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE",
        "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT",
        "DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS",
        "DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE",
        "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
        "DOCCHAIN_DIAGNOSTICS__SPANS",
        "PGOPTIONS",
        "DOCCHAIN_*",
    ];
    for key in keys {
        assert_eq!(Setting::new(key).as_str(), key);
    }
    for key in [
        "DOCCHAIN_MIGRATION__USER",
        "DOCCHAIN_MIGRATION__PASSWORD",
        "DOCCHAIN_MIGRATION__PASSWORD_FILE",
        "DOCCHAIN_MIGRATION__OTHER",
    ] {
        assert_eq!(Setting::new(key), Setting::AnyMigration);
    }
    let runtime = format!("DOCCHAIN_{}", "INVENTED__KEY");
    for key in [
        runtime.as_str(),
        "DOCCHAIN_database__host",
        "PGPASSWORD",
        "",
    ] {
        assert_eq!(Setting::new(key), Setting::Any, "{key}");
    }
}

#[test]
fn setting_reasons_map_every_config_reason_and_fail_safe() {
    for reason in [
        "is required",
        "must be a lower-case PostgreSQL identifier",
        "must not be public; use a schema the migration owner owns",
        "must differ from DOCCHAIN_MIGRATION__USER",
        "must not be set for the server; only docchain-migrate reads it",
        "must not be empty",
        "must be from 2 through 64",
        "must be a socket address",
        "must be from 1 through 1024",
        "must be an absolute non-root path",
        "must be from 1 through 100000",
        "must be from 1 through 500",
        "must not be set; use DOCCHAIN_DATABASE__SCHEMA",
        "name is not Unicode",
        "value is not Unicode",
        "cannot read secret file",
        "secret file is empty",
        "must be canonical unpadded base64url",
        "must encode exactly 32 bytes",
        "has an invalid value",
        "must be from 1 through 60000",
        "requires at least one path",
        "must be on or off",
    ] {
        let mapped = SettingReason::new(reason);
        assert_eq!(mapped.as_str(), reason);
        assert_ne!(mapped, SettingReason::Invalid, "{reason}");
    }
    let runtime = format!("{} {}", "is required", "/private/secret");
    for reason in [runtime.as_str(), "Is required", ""] {
        assert_eq!(SettingReason::new(reason), SettingReason::Invalid);
    }
}

#[test]
fn records_serialize_with_closed_field_sets() {
    let span = Span {
        request_id: 7,
        operation: Operation::SendCopy,
        outcome: Outcome::Ok,
        duration_us: 42,
    };
    for (record, kind) in [
        (Record::Request(span), "request"),
        (Record::UseCase(span), "use-case"),
    ] {
        let value = serde_json::to_value(record).expect("record");
        assert_eq!(
            keys(&value),
            [
                "duration_us",
                "operation",
                "outcome",
                "record",
                "request_id"
            ]
        );
        assert_eq!(value["record"], kind);
        assert_eq!(value["operation"], "send-copy");
        assert_eq!(value["outcome"], "ok");
        assert_eq!(
            (value["request_id"].as_u64(), value["duration_us"].as_u64()),
            (Some(7), Some(42))
        );
    }
    let step = serde_json::to_value(Record::StartupFailed(StartupFailure::at(
        StartupStep::DocumentStoreRoot,
    )))
    .expect("record");
    assert_eq!(
        step,
        serde_json::json!({"record": "startup-failed", "step": "document store root"})
    );
    let configuration = serde_json::to_value(Record::StartupFailed(StartupFailure::configuration(
        Setting::DatabasePort,
        SettingReason::InvalidValue,
    )))
    .expect("record");
    assert_eq!(
        configuration,
        serde_json::json!({
            "record": "startup-failed",
            "step": "configuration",
            "setting": "DOCCHAIN_DATABASE__PORT",
            "reason": "has an invalid value"
        })
    );
    // A configuration step always names a setting and reason, the fallback if none is given.
    assert_eq!(
        StartupFailure::at(StartupStep::Configuration),
        StartupFailure::configuration(Setting::Any, SettingReason::Invalid)
    );
}

#[test]
fn writer_thread_writes_one_line_per_record_in_order() {
    let (diagnostics, memory) = recording();
    diagnostics.open_request(Operation::Live).close(Outcome::Ok);
    diagnostics
        .open_request(Operation::Ready)
        .close(Outcome::NotReady);
    diagnostics.startup_failed(StartupFailure::at(StartupStep::HttpListener));
    assert!(diagnostics.flush(Duration::from_secs(5)));
    let lines = memory.lines();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        (
            &lines[0]["request_id"],
            &lines[0]["operation"],
            &lines[0]["outcome"]
        ),
        (&Value::from(1), &Value::from("live"), &Value::from("ok"))
    );
    assert_eq!(
        (
            &lines[1]["request_id"],
            &lines[1]["operation"],
            &lines[1]["outcome"]
        ),
        (
            &Value::from(2),
            &Value::from("ready"),
            &Value::from("not-ready")
        )
    );
    assert_eq!(lines[2]["step"], "HTTP listener");
    assert_eq!(dropped(&diagnostics), 0);
}

#[test]
fn use_case_span_repeats_the_request_id_and_operation() {
    let (diagnostics, memory) = recording();
    let request = diagnostics.open_request(Operation::Accept);
    let scope = request.scope.clone();
    let result: Result<(), ServiceError> =
        scope.run_sync(|| Err(ServiceError::Application(ApplicationError::Forbidden)));
    assert!(result.is_err());
    request.close(Outcome::Forbidden);
    assert!(diagnostics.flush(Duration::from_secs(5)));
    let lines = memory.lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["record"], "use-case");
    assert_eq!(lines[1]["record"], "request");
    for line in &lines {
        assert_eq!(line["request_id"], 1);
        assert_eq!(line["operation"], "accept");
        assert_eq!(line["outcome"], "forbidden");
    }
    assert!(lines[0]["duration_us"].as_u64() <= lines[1]["duration_us"].as_u64());
    // Use-case spans never count; only the request did.
    assert_eq!(
        cells(&diagnostics),
        [(Operation::Accept, Outcome::Forbidden, 1)]
    );
}

#[test]
fn a_dropped_request_or_use_case_records_cancelled_exactly_once() {
    let (diagnostics, memory) = recording();
    let request = diagnostics.open_request(Operation::SendCopy);
    let scope = request.scope.clone();
    let mut pending = Box::pin(scope.run(std::future::pending::<Result<(), ServiceError>>()));
    // Poll the use case once so its span opens, then drop both.
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    assert!(pending.as_mut().poll(&mut context).is_pending());
    drop(pending);
    drop(request);
    assert!(diagnostics.flush(Duration::from_secs(5)));
    let lines = memory.lines();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert_eq!(line["outcome"], "cancelled");
    }
    assert_eq!(
        cells(&diagnostics),
        [(Operation::SendCopy, Outcome::Cancelled, 1)]
    );
    // A closed span records nothing more when it drops.
    diagnostics.open_request(Operation::Live).close(Outcome::Ok);
    assert!(diagnostics.flush(Duration::from_secs(5)));
    assert_eq!(memory.lines().len(), 3);
}

#[test]
fn each_counter_cell_increments_exactly_once_per_request() {
    let diagnostics = Diagnostics::discarding();
    for operation in Operation::ALL {
        for outcome in Outcome::ALL {
            diagnostics.open_request(operation).close(outcome);
        }
    }
    let snapshot = diagnostics.counters().read();
    assert_eq!(snapshot.counters.len(), Operation::COUNT * Outcome::COUNT);
    assert_eq!(snapshot.counters.len(), 242);
    let mut expected = Vec::new();
    for operation in Operation::ALL {
        for outcome in Outcome::ALL {
            expected.push((operation, outcome, 1));
        }
    }
    assert_eq!(cells(&diagnostics), expected);
    // Discarding writes nothing and so drops nothing.
    assert_eq!(snapshot.dropped_records, 0);
}

#[test]
fn a_full_queue_drops_and_counts_without_blocking_and_counters_stay_exact() {
    let (diagnostics, _receiver) = stalled(1);
    let started = Instant::now();
    for _ in 0..3 {
        diagnostics.open_request(Operation::Live).close(Outcome::Ok);
    }
    assert!(started.elapsed() < Duration::from_secs(1), "never blocks");
    assert_eq!(dropped(&diagnostics), 2);
    assert_eq!(cells(&diagnostics), [(Operation::Live, Outcome::Ok, 3)]);
}

#[test]
fn a_closed_queue_drops_and_counts_every_record() {
    let (diagnostics, receiver) = stalled(QUEUE_CAPACITY);
    drop(receiver);
    diagnostics
        .open_request(Operation::Ready)
        .close(Outcome::Ok);
    diagnostics.startup_failed(StartupFailure::at(StartupStep::HttpListener));
    assert_eq!(dropped(&diagnostics), 2);
    assert_eq!(cells(&diagnostics), [(Operation::Ready, Outcome::Ok, 1)]);
}

#[test]
fn spans_off_writes_no_span_but_counts_and_reports_startup() {
    let (diagnostics, memory) = recording();
    let diagnostics = diagnostics.with_spans(false);
    let request = diagnostics.open_request(Operation::ListInbox);
    let _ = request
        .scope
        .clone()
        .run_sync(|| Ok::<(), ServiceError>(()));
    request.close(Outcome::Ok);
    diagnostics.startup_failed(StartupFailure::at(StartupStep::SignalListener));
    assert!(diagnostics.flush(Duration::from_secs(5)));
    let lines = memory.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["record"], "startup-failed");
    assert_eq!(
        cells(&diagnostics),
        [(Operation::ListInbox, Outcome::Ok, 1)]
    );
}

#[test]
fn request_ids_are_a_sequence_from_one() {
    let diagnostics = Diagnostics::discarding();
    let ids: Vec<u64> = (0..3)
        .map(|_| diagnostics.open_request(Operation::Live).scope.request_id)
        .collect();
    assert_eq!(ids, [1, 2, 3]);
}

#[test]
fn counters_document_is_versioned_and_closed() {
    let diagnostics = Diagnostics::discarding();
    diagnostics
        .open_request(Operation::SendCopy)
        .close(Outcome::Ok);
    diagnostics
        .open_request(Operation::SendCopy)
        .close(Outcome::Ok);
    diagnostics
        .open_request(Operation::Unmatched)
        .close(Outcome::NotFound);
    let value = serde_json::to_value(diagnostics.counters().read()).expect("document");
    assert_eq!(
        value,
        serde_json::json!({
            "version": 1,
            "counters": [
                {"operation": "send-copy", "outcome": "ok", "count": 2},
                {"operation": "unmatched", "outcome": "not-found", "count": 1}
            ],
            "dropped_records": 0
        })
    );
}
