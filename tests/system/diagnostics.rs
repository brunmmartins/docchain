//! Diagnostics: closed-schema request and use-case records, the operator-only outcome counters,
//! and startup-failure records, both in process and on the real server binary's two streams.
#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use docchain_application::Limits;
use docchain_server::{
    DemoHarness, HttpConfig,
    diagnostics::{Captured, Diagnostics, Operation, Outcome, Setting, SettingReason, StartupStep},
    router, router_with_diagnostics,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

const SENDER: &str = "wal_0000000000000001";
const RECIPIENT: &str = "wal_0000000000000002";
const UNKEYED: &str = "wal_0000000000000004";

/// Values seeded into requests that must never reach a diagnostic record or output stream.
const HEADER_CANARY: &str = "canaryheader7f3a9c";
const QUERY_CANARY: &str = "canaryquery5e1b2d";
const PATH_CANARY: &str = "canarypath9d4c6e";
const BODY_CANARY: &str = "canarybody2a8f0b";
const PLAINTEXT: [&str; 3] = ["Please provide", "SYN-APP0001", "invented record"];

// ---------------------------------------------------------------------------------------------
// A raw HTTP/1.1 client and in-process serving.
// ---------------------------------------------------------------------------------------------

struct Reply {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON body")
    }

    fn category(&self) -> String {
        self.json()["category"]
            .as_str()
            .expect("problem category")
            .to_owned()
    }
}

async fn serve(application: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, application).await });
    address
}

/// An in-process router whose diagnostics write into a captured buffer.
async fn instrumented(harness: &DemoHarness, spans: bool) -> (SocketAddr, Captured) {
    let (diagnostics, captured) = Diagnostics::capture();
    let application = router_with_diagnostics(
        harness.service(),
        HttpConfig::default(),
        diagnostics.with_spans(spans),
    );
    (serve(application).await, captured)
}

async fn send(address: SocketAddr, request: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request).await.expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut response))
        .await
        .expect("response within 30 s")
        .expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator");
    Reply {
        status: std::str::from_utf8(&response[9..12])
            .expect("status digits")
            .parse()
            .expect("status code"),
        head: String::from_utf8_lossy(&response[..split]).into_owned(),
        body: response[split + 4..].to_vec(),
    }
}

fn get(path: &str, headers: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n")
        .into_bytes()
}

fn post(path: &str, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn bearer(credential: &str) -> String {
    format!("Authorization: Bearer {credential}\r\n")
}

/// Client correlation and other seeded headers, all of which the server must ignore.
fn seeded_headers(credential: &str) -> String {
    format!(
        "{}X-Request-Id: {HEADER_CANARY}\r\ntraceparent: 00-{HEADER_CANARY}-01\r\nX-Canary: {HEADER_CANARY}\r\n",
        bearer(credential)
    )
}

fn example_document() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../schemas/service-application/example.json"
    ))
    .expect("example document")
}

/// A send-copy body for `recipient`; `version`, `nonce`, and `key` make it distinct.
fn send_body(recipient: &str, version: u64, nonce: u8, key: &str) -> Value {
    json!({
        "sender": SENDER,
        "recipient": recipient,
        "document_id": "doc_0000000000000001",
        "document_version": version,
        "request_nonce": URL_SAFE_NO_PAD.encode([nonce; 16]),
        "idempotency_key": key,
        "schema_id": "urn:docchain:schema:service-application:1.0.0",
        "schema_version": "1.0.0",
        "document": example_document(),
    })
}

async fn send_copy(address: SocketAddr, harness: &DemoHarness, body: &Value) -> Reply {
    send(
        address,
        &post(
            "/v1/send-copies",
            &bearer(&harness.sender_credential),
            &body.to_string(),
        ),
    )
    .await
}

async fn accept(address: SocketAddr, harness: &DemoHarness, exchange: &str, key: &str) -> Reply {
    send(
        address,
        &post(
            &format!("/v1/exchanges/{exchange}/acceptances"),
            &bearer(&harness.recipient_credential),
            &json!({ "idempotency_key": key }).to_string(),
        ),
    )
    .await
}

fn exchange_of(reply: &Reply) -> String {
    assert_eq!(
        reply.status,
        201,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    reply.json()["exchange_id"]
        .as_str()
        .expect("exchange id")
        .to_owned()
}

// ---------------------------------------------------------------------------------------------
// The closed record schema.
// ---------------------------------------------------------------------------------------------

fn texts<const N: usize>(values: [&'static str; N]) -> BTreeSet<&'static str> {
    values.into_iter().collect()
}

fn keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// Parses one line and asserts it is a closed record: an exact field set, documented enum values,
/// and integers. Returns the record.
fn closed_record(line: &str) -> Value {
    let record: Value = serde_json::from_str(line).unwrap_or_else(|_| panic!("JSON: {line}"));
    let operations = texts(Operation::ALL.map(Operation::as_str));
    let outcomes = texts(Outcome::ALL.map(Outcome::as_str));
    match record["record"].as_str() {
        Some("request" | "use-case") => {
            assert_eq!(
                keys(&record),
                [
                    "duration_us",
                    "operation",
                    "outcome",
                    "record",
                    "request_id"
                ],
                "{line}"
            );
            assert!(
                record["request_id"].as_u64().is_some_and(|id| id >= 1),
                "{line}"
            );
            assert!(record["duration_us"].is_u64(), "{line}");
            assert!(
                operations.contains(record["operation"].as_str().expect("operation")),
                "{line}"
            );
            assert!(
                outcomes.contains(record["outcome"].as_str().expect("outcome")),
                "{line}"
            );
        }
        Some("startup-failed") => {
            let step = record["step"].as_str().expect("step");
            assert!(
                texts(StartupStep::ALL.map(StartupStep::as_str)).contains(step),
                "{line}"
            );
            if step == "configuration" {
                assert_eq!(
                    keys(&record),
                    ["reason", "record", "setting", "step"],
                    "{line}"
                );
                assert!(
                    texts(Setting::ALL.map(Setting::as_str))
                        .contains(record["setting"].as_str().expect("setting")),
                    "{line}"
                );
                assert!(
                    texts(SettingReason::ALL.map(SettingReason::as_str))
                        .contains(record["reason"].as_str().expect("reason")),
                    "{line}"
                );
            } else {
                assert_eq!(keys(&record), ["record", "step"], "{line}");
            }
        }
        _ => panic!("unknown record: {line}"),
    }
    record
}

/// Every string of at least twelve characters in a JSON value: identifiers, commitments, keys,
/// fingerprints, hashes, signatures, and challenges a response carried.
fn long_strings(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::String(text) if text.len() >= 12 => {
            into.insert(text.clone());
        }
        Value::Array(items) => items.iter().for_each(|item| long_strings(item, into)),
        Value::Object(fields) => fields.values().for_each(|item| long_strings(item, into)),
        _ => {}
    }
}

/// Values that must never appear in diagnostics: every credential, wallet identifier, seeded
/// canary, plaintext fragment, configured path and secret, and every long value a successful
/// response returned.
fn prohibited(harness: &DemoHarness, returned: &BTreeSet<String>) -> Vec<String> {
    let mut values: Vec<String> = [
        harness.sender_credential.as_str(),
        harness.recipient_credential.as_str(),
        harness.unrelated_credential.as_str(),
        harness.unkeyed_credential.as_str(),
        harness.auditor_credential.as_str(),
        harness.operator_credential.as_str(),
        SENDER,
        RECIPIENT,
        UNKEYED,
        "wal_",
        "doc_",
        "exc_",
        "idem_",
        HEADER_CANARY,
        QUERY_CANARY,
        PATH_CANARY,
        BODY_CANARY,
    ]
    .into_iter()
    .chain(PLAINTEXT)
    .map(str::to_owned)
    .collect();
    for (key, value) in harness.server_environment() {
        if key.ends_with("_FILE") || key.ends_with("_FILES") {
            for path in value.split(',') {
                if let Ok(secret) = std::fs::read_to_string(path) {
                    values.extend(
                        secret
                            .lines()
                            .map(str::trim)
                            .filter(|line| line.len() >= 8)
                            .map(str::to_owned),
                    );
                }
            }
        }
        let sensitive = [
            "_FILE",
            "_FILES",
            "_ROOT",
            "__SCHEMA",
            "__USER",
            "__PASSWORD",
            "_FINGERPRINT",
        ]
        .iter()
        .any(|suffix| key.ends_with(suffix));
        if sensitive && value.len() >= 8 {
            values.extend(value.split(',').map(str::to_owned));
        }
    }
    values.push(harness.document_root().display().to_string());
    values.extend(returned.iter().cloned());
    values.push(URL_SAFE_NO_PAD.encode(harness.expected_audit_fingerprint()));
    values
}

fn assert_excludes(output: &str, values: &[String]) {
    for value in values {
        assert!(
            !output.contains(value.as_str()),
            "diagnostics hold {value:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// AC1
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn emits_request_and_use_case_spans() {
    let harness = DemoHarness::new().await.expect("harness");
    let (address, captured) = instrumented(&harness, true).await;
    let delivered = send(
        address,
        &post(
            "/v1/send-copies",
            &seeded_headers(&harness.sender_credential),
            &send_body(RECIPIENT, 1, 0xf0, "idem_0000000000000001").to_string(),
        ),
    )
    .await;
    let exchange = exchange_of(&delivered);
    let accepted = send(
        address,
        &post(
            &format!("/v1/exchanges/{exchange}/acceptances"),
            &format!(
                "{}X-Request-Id: 424242\r\n",
                bearer(&harness.recipient_credential)
            ),
            r#"{"idempotency_key":"idem_accept0000000001"}"#,
        ),
    )
    .await;
    assert_eq!(accepted.status, 200);
    // A response never carries the request ID.
    for reply in [&delivered, &accepted] {
        assert!(!reply.head.to_ascii_lowercase().contains("request-id"));
    }

    let records: Vec<Value> = captured
        .lines()
        .iter()
        .map(|line| closed_record(line))
        .collect();
    let of_kind = |kind: &str| -> Vec<&Value> {
        records
            .iter()
            .filter(|record| record["record"] == kind)
            .collect()
    };
    let requests = of_kind("request");
    let use_cases = of_kind("use-case");
    assert_eq!((requests.len(), use_cases.len()), (2, 2), "{records:?}");
    for (request, operation) in requests.iter().zip(["send-copy", "accept"]) {
        assert_eq!(request["operation"], operation);
        assert_eq!(request["outcome"], "ok");
        let use_case = use_cases
            .iter()
            .find(|use_case| use_case["request_id"] == request["request_id"])
            .expect("a use-case span shares the request ID");
        assert_eq!(use_case["operation"], operation);
        assert_eq!(use_case["outcome"], "ok");
        assert!(use_case["duration_us"].as_u64() <= request["duration_us"].as_u64());
    }
    // IDs differ across requests and never come from the client's correlation header.
    assert_ne!(requests[0]["request_id"], requests[1]["request_id"]);
    for record in &records {
        assert_ne!(record["request_id"], 424_242);
    }
    assert_excludes(
        &captured.lines().join("\n"),
        &[HEADER_CANARY.to_owned(), exchange],
    );

    // With spans off, no span record appears, but counters still count.
    let (quiet, captured) = instrumented(&harness, false).await;
    let second = send_copy(
        quiet,
        &harness,
        &send_body(RECIPIENT, 2, 0xf1, "idem_0000000000000002"),
    )
    .await;
    exchange_of(&second);
    let counters = send(
        quiet,
        &get(
            "/operations/counters",
            &bearer(&harness.operator_credential),
        ),
    )
    .await;
    assert_eq!(counters.status, 200);
    assert_eq!(
        counters.json()["counters"],
        json!([{"operation": "send-copy", "outcome": "ok", "count": 1}])
    );
    assert_eq!(captured.lines(), Vec::<String>::new());
}

// ---------------------------------------------------------------------------------------------
// AC2, in process
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn diagnostics_exclude_confidential_values() {
    let harness = DemoHarness::new().await.expect("harness");
    let (address, captured) = instrumented(&harness, true).await;
    let mut returned = BTreeSet::new();
    let mut remember = |reply: &Reply| {
        if (200..300).contains(&reply.status) && !reply.body.is_empty() {
            long_strings(&reply.json(), &mut returned);
        }
    };
    let seeded = |credential: &str| seeded_headers(credential);

    // The first-exchange journeys, each with seeded headers and a seeded query.
    let body = send_body(RECIPIENT, 1, 0xf0, "idem_0000000000000001").to_string();
    let delivered = send(
        address,
        &post(
            &format!("/v1/send-copies?{QUERY_CANARY}={QUERY_CANARY}"),
            &seeded(&harness.sender_credential),
            &body,
        ),
    )
    .await;
    let exchange = exchange_of(&delivered);
    remember(&delivered);
    let replayed = send(
        address,
        &post(
            "/v1/send-copies",
            &seeded(&harness.sender_credential),
            &body,
        ),
    )
    .await;
    assert_eq!(replayed.status, 201);
    remember(&replayed);
    let inbox = send(
        address,
        &get(
            &format!("/v1/inboxes/{RECIPIENT}?{QUERY_CANARY}"),
            &seeded(&harness.recipient_credential),
        ),
    )
    .await;
    assert_eq!(inbox.status, 200);
    remember(&inbox);
    let document = format!("/v1/exchanges/{exchange}/document");
    let read = send(
        address,
        &get(&document, &seeded(&harness.recipient_credential)),
    )
    .await;
    assert_eq!(read.status, 200);
    remember(&read);
    let accepted = send(
        address,
        &post(
            &format!("/v1/exchanges/{exchange}/acceptances"),
            &seeded(&harness.recipient_credential),
            r#"{"idempotency_key":"idem_accept0000000001"}"#,
        ),
    )
    .await;
    assert_eq!(accepted.status, 200);
    remember(&accepted);
    let sender_read = send(
        address,
        &get(&document, &seeded(&harness.sender_credential)),
    )
    .await;
    assert_eq!(sender_read.status, 200);

    // Rejected schema, unauthorized read, replay with changed content, and seeded paths and bodies.
    let mut unsupported = send_body(RECIPIENT, 3, 0xf3, "idem_0000000000000003");
    unsupported["schema_id"] = json!(format!("urn:docchain:schema:{BODY_CANARY}:1.0.0"));
    let rejected = send_copy(address, &harness, &unsupported).await;
    assert_eq!(rejected.category(), "unsupported-schema");
    let unauthorized = send(
        address,
        &get(&document, &seeded(&harness.unrelated_credential)),
    )
    .await;
    assert_eq!(unauthorized.status, 403);
    let changed = send_body(RECIPIENT, 2, 0xf0, "idem_0000000000000001");
    let replay = send_copy(address, &harness, &changed).await;
    assert_eq!(replay.category(), "replay");
    let seeded_path = send(
        address,
        &get(
            &format!("/v1/exchanges/{PATH_CANARY}/document"),
            &seeded(&harness.recipient_credential),
        ),
    )
    .await;
    assert_eq!(seeded_path.status, 422);
    let unmatched = send(address, &get(&format!("/{PATH_CANARY}/{QUERY_CANARY}"), "")).await;
    assert_eq!(unmatched.status, 404);
    let seeded_body = send(
        address,
        &post(
            "/v1/send-copies",
            &seeded(&harness.sender_credential),
            &format!(r#"{{"{BODY_CANARY}":"{}"}}"#, PLAINTEXT[0]),
        ),
    )
    .await;
    assert_eq!(seeded_body.status, 422);

    // The audit proof routes: key, verify, export start and continuation, verify with a held head.
    let auditor = seeded(&harness.auditor_credential);
    let key = send(address, &get("/v1/audit/key", &auditor)).await;
    assert_eq!(key.status, 200);
    remember(&key);
    let verified = send(address, &get("/v1/audit/verify", &auditor)).await;
    assert_eq!(verified.status, 200);
    remember(&verified);
    let head = verified.json()["head"].clone();
    let held = format!(
        "/v1/audit/verify?head_sequence={}&head_event_hash={}&head_signature={}",
        head["sequence"],
        head["event_hash"].as_str().expect("hash"),
        head["signature"].as_str().expect("signature")
    );
    let held_verify = send(address, &get(&held, &auditor)).await;
    assert_eq!(held_verify.status, 200);
    remember(&held_verify);
    let challenge = URL_SAFE_NO_PAD.encode([0x5a; 32]);
    let start = send(
        address,
        &post(
            "/v1/audit/events/export",
            &auditor,
            &json!({"challenge": challenge, "limit": 1}).to_string(),
        ),
    )
    .await;
    assert_eq!(start.status, 200);
    remember(&start);
    let page = start.json();
    let continuation = send(
        address,
        &post(
            "/v1/audit/events/export",
            &auditor,
            &json!({
                "manifest": page["manifest"],
                "manifest_signature": page["manifest_signature"],
                "after_sequence": page["next_after_sequence"],
                "limit": 1
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(continuation.status, 200);
    remember(&continuation);
    let proof_in_query = send(
        address,
        &get(&format!("/v1/audit/key?fingerprint={challenge}"), &auditor),
    )
    .await;
    assert_eq!(proof_in_query.status, 422);

    // The counters read, as the operator and as an untrusted client.
    let counters = send(
        address,
        &get(
            "/operations/counters",
            &seeded(&harness.operator_credential),
        ),
    )
    .await;
    assert_eq!(counters.status, 200);
    let untrusted = send(
        address,
        &get("/operations/counters", &seeded(&harness.sender_credential)),
    )
    .await;
    assert_eq!(untrusted.status, 403);

    let lines = captured.lines();
    let records: Vec<Value> = lines.iter().map(|line| closed_record(line)).collect();
    assert!(
        records
            .iter()
            .any(|record| record["operation"] == "export-audit-events"
                && record["record"] == "request"
                && record["outcome"] == "ok")
    );
    assert!(returned.contains(&exchange));
    assert!(returned.contains(challenge.as_str()));
    returned.insert(challenge);
    returned.insert(body);
    assert_excludes(&lines.join("\n"), &prohibited(&harness, &returned));
}

// ---------------------------------------------------------------------------------------------
// AC3
// ---------------------------------------------------------------------------------------------

type Cells = BTreeMap<(String, String), u64>;

/// Reads the counters as the operator and asserts the closed, versioned document.
async fn cells(address: SocketAddr, harness: &DemoHarness) -> Cells {
    let reply = send(
        address,
        &get(
            "/operations/counters",
            &bearer(&harness.operator_credential),
        ),
    )
    .await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert!(
        reply
            .head
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
    );
    assert!(
        reply
            .head
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    let document = reply.json();
    assert_eq!(keys(&document), ["counters", "dropped_records", "version"]);
    assert_eq!(document["version"], 1);
    assert!(document["dropped_records"].is_u64());
    let operations = texts(Operation::ALL.map(Operation::as_str));
    let outcomes = texts(Outcome::ALL.map(Outcome::as_str));
    let entries = document["counters"].as_array().expect("counters");
    assert!(entries.len() <= 242);
    let mut cells = Cells::new();
    for entry in entries {
        assert_eq!(keys(entry), ["count", "operation", "outcome"]);
        let operation = entry["operation"].as_str().expect("operation");
        let outcome = entry["outcome"].as_str().expect("outcome");
        assert!(operations.contains(operation) && outcomes.contains(outcome));
        let count = entry["count"].as_u64().expect("count");
        assert!(count >= 1);
        assert!(
            cells
                .insert((operation.to_owned(), outcome.to_owned()), count)
                .is_none(),
            "one entry per cell"
        );
    }
    cells
}

/// Asserts the whole-matrix change between two reads is exactly `expected`, plus the first
/// read's own `read-counters`/`ok`.
fn assert_delta(before: &Cells, after: &Cells, expected: &[(&str, &str, u64)]) {
    let mut wanted = Cells::new();
    for (operation, outcome, count) in expected.iter().copied().chain([("read-counters", "ok", 1)])
    {
        *wanted
            .entry((operation.to_owned(), outcome.to_owned()))
            .or_default() += count;
    }
    let mut delta = Cells::new();
    for (cell, count) in after {
        let earlier = before.get(cell).copied().unwrap_or(0);
        assert!(*count >= earlier, "{cell:?} decreased");
        if *count > earlier {
            delta.insert(cell.clone(), count - earlier);
        }
    }
    for cell in before.keys() {
        assert!(after.contains_key(cell), "{cell:?} vanished");
    }
    assert_eq!(delta, wanted);
}

/// Sends `request` and asserts it changed exactly one cell, `operation`/`outcome`, by one.
async fn expect_cell(
    address: SocketAddr,
    harness: &DemoHarness,
    request: &[u8],
    operation: &str,
    outcome: &str,
) -> Reply {
    let before = cells(address, harness).await;
    let reply = send(address, request).await;
    assert_delta(
        &before,
        &cells(address, harness).await,
        &[(operation, outcome, 1)],
    );
    reply
}

#[tokio::test]
async fn outcome_counters_are_bounded() {
    let harness = DemoHarness::new().await.expect("harness");
    let address = serve(router(harness.service(), HttpConfig::default())).await;
    let sender = bearer(&harness.sender_credential);
    let recipient = bearer(&harness.recipient_credential);
    let auditor = bearer(&harness.auditor_credential);
    let operator = bearer(&harness.operator_credential);
    let unknown = bearer("unknown-credential");
    let reached = |reply: Reply, status: u16| {
        assert_eq!(
            reply.status,
            status,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        reply
    };

    // Every operation once, successfully.
    reached(
        expect_cell(address, &harness, &get("/health/live", ""), "live", "ok").await,
        204,
    );
    reached(
        expect_cell(address, &harness, &get("/health/ready", ""), "ready", "ok").await,
        204,
    );
    let body = send_body(RECIPIENT, 1, 0xf0, "idem_0000000000000001");
    let delivered = expect_cell(
        address,
        &harness,
        &post("/v1/send-copies", &sender, &body.to_string()),
        "send-copy",
        "ok",
    )
    .await;
    let exchange = exchange_of(&delivered);
    let document = format!("/v1/exchanges/{exchange}/document");
    reached(
        expect_cell(
            address,
            &harness,
            &get(&document, &recipient),
            "read-document",
            "ok",
        )
        .await,
        200,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &get(&format!("/v1/inboxes/{RECIPIENT}"), &recipient),
            "list-inbox",
            "ok",
        )
        .await,
        200,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &post(
                &format!("/v1/exchanges/{exchange}/acceptances"),
                &recipient,
                r#"{"idempotency_key":"idem_accept0000000001"}"#,
            ),
            "accept",
            "ok",
        )
        .await,
        200,
    );
    let verified = reached(
        expect_cell(
            address,
            &harness,
            &get("/v1/audit/verify", &auditor),
            "verify-audit",
            "ok",
        )
        .await,
        200,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &get("/v1/audit/key", &auditor),
            "audit-key",
            "ok",
        )
        .await,
        200,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &post(
                "/v1/audit/events/export",
                &auditor,
                &json!({"challenge": URL_SAFE_NO_PAD.encode([1; 32])}).to_string(),
            ),
            "export-audit-events",
            "ok",
        )
        .await,
        200,
    );

    // The counters route: authenticate first, then refuse a query or body, then authorize.
    let counters_body = |headers: &str, body: &str| {
        format!(
            "GET /operations/counters HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    for (request, status, outcome) in [
        (get("/operations/counters", ""), 401, "unauthenticated"),
        (
            get("/operations/counters?all=1", ""),
            401,
            "unauthenticated",
        ),
        (
            get("/operations/counters", &unknown),
            401,
            "unauthenticated",
        ),
        (
            get("/operations/counters?all=1", &unknown),
            401,
            "unauthenticated",
        ),
        (get("/operations/counters", &sender), 403, "forbidden"),
        (get("/operations/counters", &auditor), 403, "forbidden"),
        (
            get("/operations/counters?all=1", &operator),
            422,
            "invalid-request",
        ),
        (counters_body(&operator, "{}"), 422, "invalid-request"),
    ] {
        let denied = expect_cell(address, &harness, &request, "read-counters", outcome).await;
        assert_eq!(
            (denied.status, denied.category()),
            (status, outcome.to_owned())
        );
        // No failed read returns a counter.
        assert_eq!(keys(&denied.json()), ["category"]);
        assert!(
            denied
                .head
                .to_ascii_lowercase()
                .contains("cache-control: no-store")
        );
    }

    // Business rejections, each from its typed error.
    let mut invalid_document = send_body(RECIPIENT, 5, 0xf5, "idem_0000000000000005");
    invalid_document["document"]["unexpected"] = json!(true);
    let mut unsupported = send_body(RECIPIENT, 6, 0xf6, "idem_0000000000000006");
    unsupported["schema_id"] = json!("urn:docchain:schema:unknown:1.0.0");
    let unkeyed = send_body(UNKEYED, 7, 0xf7, "idem_0000000000000007");
    let replay = send_body(RECIPIENT, 8, 0xf0, "idem_0000000000000001");
    for (body, outcome) in [
        (invalid_document.to_string(), "invalid-document"),
        (unsupported.to_string(), "unsupported-schema"),
        (unkeyed.to_string(), "key-binding"),
        (replay.to_string(), "replay"),
        ("not json".to_owned(), "invalid-request"),
    ] {
        let reply = expect_cell(
            address,
            &harness,
            &post("/v1/send-copies", &sender, &body),
            "send-copy",
            outcome,
        )
        .await;
        assert_eq!(reply.category(), outcome);
    }
    reached(
        expect_cell(
            address,
            &harness,
            &get("/v1/send-copies", &sender),
            "send-copy",
            "method-not-allowed",
        )
        .await,
        405,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &post("/health/live", "", ""),
            "live",
            "method-not-allowed",
        )
        .await,
        405,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &post(
                "/v1/send-copies",
                &sender,
                &"x".repeat(docchain_domain::MAX_DOCUMENT_BYTES + 1),
            ),
            "send-copy",
            "payload-too-large",
        )
        .await,
        413,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &get("/v1/exchanges/%FF/document", &recipient),
            "read-document",
            "rejected",
        )
        .await,
        400,
    );
    reached(
        expect_cell(
            address,
            &harness,
            &get("/nowhere", ""),
            "unmatched",
            "not-found",
        )
        .await,
        404,
    );

    // Many distinct unmatched paths grow only one cell.
    let before = cells(address, &harness).await;
    for index in 0..1_000 {
        let reply = send(
            address,
            &get(&format!("/unmatched/{index}/{PATH_CANARY}"), ""),
        )
        .await;
        assert_eq!(reply.status, 404);
    }
    let after = cells(address, &harness).await;
    assert_delta(&before, &after, &[("unmatched", "not-found", 1_000)]);

    // Stored-data failures.
    harness
        .alter_envelope(&docchain_domain::ExchangeId::new(exchange.clone()).expect("exchange"))
        .await
        .expect("alter envelope");
    let broken = expect_cell(
        address,
        &harness,
        &get(&document, &recipient),
        "read-document",
        "invalid-envelope",
    )
    .await;
    assert_eq!(broken.category(), "invalid-envelope");
    let head = verified.json()["head"].clone();
    harness.truncate_last_event().await.expect("truncate");
    let held = format!(
        "/v1/audit/verify?head_sequence={}&head_event_hash={}&head_signature={}",
        head["sequence"],
        head["event_hash"].as_str().expect("hash"),
        head["signature"].as_str().expect("signature")
    );
    let tampered = expect_cell(
        address,
        &harness,
        &get(&held, &auditor),
        "verify-audit",
        "integrity-failure",
    )
    .await;
    assert_eq!(tampered.category(), "integrity-failure");

    // A missing document root: readiness is not ready, and a send reports the dependency.
    harness
        .remove_document_root()
        .await
        .expect("remove document root");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    reached(
        expect_cell(
            address,
            &harness,
            &get("/health/ready", ""),
            "ready",
            "not-ready",
        )
        .await,
        503,
    );
    let unavailable = expect_cell(
        address,
        &harness,
        &post(
            "/v1/send-copies",
            &sender,
            &send_body(RECIPIENT, 9, 0xf9, "idem_0000000000000009").to_string(),
        ),
        "send-copy",
        "dependency-failure",
    )
    .await;
    assert_eq!(unavailable.category(), "dependency-failure");
}

#[tokio::test]
async fn overload_timeout_and_limit_outcomes_are_counted() {
    // Overload: one admitted request holds the only permit.
    let harness = DemoHarness::new().await.expect("harness");
    let gate = harness.after_put_new_gate();
    let single = serve(router(
        harness.service(),
        HttpConfig {
            max_in_flight: 1,
            ..HttpConfig::default()
        },
    ))
    .await;
    let before = cells(single, &harness).await;
    gate.arm();
    let held = tokio::spawn({
        let body = send_body(RECIPIENT, 1, 0xf0, "idem_0000000000000001").to_string();
        let credential = harness.sender_credential.clone();
        async move {
            send(
                single,
                &post("/v1/send-copies", &bearer(&credential), &body),
            )
            .await
        }
    });
    gate.reached(1).await;
    let refused = send(
        single,
        &get(
            &format!("/v1/inboxes/{RECIPIENT}"),
            &bearer(&harness.recipient_credential),
        ),
    )
    .await;
    assert_eq!(
        (refused.status, refused.category()),
        (503, "overloaded".to_owned())
    );
    gate.open();
    exchange_of(&held.await.expect("held send"));
    assert_delta(
        &before,
        &cells(single, &harness).await,
        &[("send-copy", "ok", 1), ("list-inbox", "overloaded", 1)],
    );

    // Timeout: the deadline passes while a send waits at the gate.
    let short = serve(router(
        harness.service(),
        HttpConfig {
            request_timeout: Duration::from_millis(300),
            ..HttpConfig::default()
        },
    ))
    .await;
    gate.arm();
    let timed_out = expect_cell(
        short,
        &harness,
        &post(
            "/v1/send-copies",
            &bearer(&harness.sender_credential),
            &send_body(RECIPIENT, 2, 0xf1, "idem_0000000000000002").to_string(),
        ),
        "send-copy",
        "timeout",
    )
    .await;
    gate.open();
    assert_eq!(
        (timed_out.status, timed_out.category()),
        (504, "timeout".to_owned())
    );

    // Pending limit and an audit beyond its event bound.
    let limited = DemoHarness::new_with_limits(Limits {
        pending_per_relationship: 1,
        audit_events: 1,
        ..Limits::default()
    })
    .await
    .expect("limited harness");
    let address = serve(router(limited.service(), HttpConfig::default())).await;
    let first = send_copy(
        address,
        &limited,
        &send_body(RECIPIENT, 1, 0xf0, "idem_0000000000000001"),
    )
    .await;
    let exchange = exchange_of(&first);
    let over = expect_cell(
        address,
        &limited,
        &post(
            "/v1/send-copies",
            &bearer(&limited.sender_credential),
            &send_body(RECIPIENT, 2, 0xf1, "idem_0000000000000002").to_string(),
        ),
        "send-copy",
        "pending-limit",
    )
    .await;
    assert_eq!(over.category(), "pending-limit");
    assert_eq!(
        accept(address, &limited, &exchange, "idem_accept0000000001")
            .await
            .status,
        200
    );
    let incomplete = expect_cell(
        address,
        &limited,
        &get("/v1/audit/verify", &bearer(&limited.auditor_credential)),
        "verify-audit",
        "audit-incomplete",
    )
    .await;
    assert_eq!(
        (incomplete.status, incomplete.category()),
        (503, "audit-incomplete".to_owned())
    );
}

// ---------------------------------------------------------------------------------------------
// The real server binary.
// ---------------------------------------------------------------------------------------------

fn free_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    listener.local_addr().expect("free port address")
}

fn spawn(environment: &[(String, String)], address: SocketAddr) -> Child {
    Command::new(env!("CARGO_BIN_EXE_docchain-server"))
        .env_clear()
        .envs(environment.iter().cloned())
        .env("DOCCHAIN_HTTP__BIND", address.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server binary")
}

/// Reads a pipe to its end on its own thread, so the server never blocks on a full pipe.
fn drain(pipe: Option<impl std::io::Read + Send + 'static>) -> std::thread::JoinHandle<String> {
    let mut pipe = pipe.expect("piped stream");
    std::thread::spawn(move || {
        let mut text = String::new();
        pipe.read_to_string(&mut text).expect("stream text");
        text
    })
}

async fn ready(address: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    stream
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    std::str::from_utf8(response.get(9..12)?).ok()?.parse().ok()
}

/// Waits up to thirty seconds for exit, asserting the process never became ready.
async fn exit_before_ready(child: &mut Child, address: SocketAddr) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("process status") {
            return status;
        }
        assert_ne!(ready(address).await, Some(204), "ready before exiting");
        if started.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            panic!("process did not exit");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One setting to replace, or, with `None`, to remove.
type Override<'a> = (&'a str, Option<&'a str>);

/// The harness's server environment with `overrides` applied; `None` removes a key.
fn environment(harness: &DemoHarness, overrides: &[Override]) -> Vec<(String, String)> {
    let mut environment = harness.server_environment();
    environment.retain(|(key, _)| !overrides.iter().any(|(name, _)| key == name));
    environment.extend(
        overrides
            .iter()
            .filter_map(|(key, value)| value.map(|value| ((*key).to_owned(), value.to_owned()))),
    );
    environment
}

#[tokio::test]
async fn startup_failure_reports_step() {
    let harness = DemoHarness::new().await.expect("harness");
    let closed_port = free_address().port().to_string();
    let (_, root) = harness.fixture_location();
    let regular_file = root.join("regular-file-root");
    std::fs::write(&regular_file, b"not a directory").expect("regular file");
    let regular_file = regular_file.display().to_string();
    let missing_key = root.join("missing").join("audit.key").display().to_string();
    let cases: [(&[Override], Value); 5] = [
        (
            &[("DOCCHAIN_DATABASE__PORT", Some("not-a-port-canary"))],
            json!({"record": "startup-failed", "step": "configuration",
                   "setting": "DOCCHAIN_DATABASE__PORT", "reason": "has an invalid value"}),
        ),
        (
            &[("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT", None)],
            json!({"record": "startup-failed", "step": "configuration",
                   "setting": "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT", "reason": "is required"}),
        ),
        (
            &[
                ("DOCCHAIN_DATABASE__HOST", Some("127.0.0.1")),
                ("DOCCHAIN_DATABASE__PORT", Some(closed_port.as_str())),
            ],
            json!({"record": "startup-failed", "step": "database connection"}),
        ),
        (
            &[("DOCCHAIN_DOCUMENT_STORE__ROOT", Some(regular_file.as_str()))],
            json!({"record": "startup-failed", "step": "document store root"}),
        ),
        (
            &[(
                "DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE",
                Some(missing_key.as_str()),
            )],
            json!({"record": "startup-failed", "step": "audit key file"}),
        ),
    ];
    let mut secrets = prohibited(&harness, &BTreeSet::new());
    secrets.extend([
        "not-a-port-canary".to_owned(),
        regular_file.clone(),
        missing_key.clone(),
        root.display().to_string(),
    ]);
    for (overrides, expected) in cases {
        let address = free_address();
        let mut child = spawn(&environment(&harness, overrides), address);
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let status = exit_before_ready(&mut child, address).await;
        let stdout = stdout.join().expect("stdout");
        let stderr = stderr.join().expect("stderr");
        assert_eq!(status.code(), Some(1), "{stdout}{stderr}");
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{stdout}");
        assert_eq!(closed_record(lines[0]), expected);
        // The existing human-readable line stays, and is the only line on standard error.
        let human: Vec<&str> = stderr.lines().collect();
        assert_eq!(human.len(), 1, "{stderr}");
        assert!(human[0].starts_with("docchain-server: "), "{stderr}");
        assert_excludes(&format!("{stdout}\n{stderr}"), &secrets);
    }
}

#[tokio::test]
async fn server_streams_hold_only_closed_records() {
    let harness = DemoHarness::new().await.expect("harness");
    let address = free_address();
    let mut child = spawn(&harness.server_environment(), address);
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let started = Instant::now();
    while ready(address).await != Some(204) {
        assert!(
            matches!(child.try_wait(), Ok(None)),
            "server exited before ready"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "server not ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut returned = BTreeSet::new();
    let body = send_body(RECIPIENT, 1, 0xf0, "idem_0000000000000001");
    let delivered = send(
        address,
        &post(
            &format!("/v1/send-copies?{QUERY_CANARY}=1"),
            &seeded_headers(&harness.sender_credential),
            &body.to_string(),
        ),
    )
    .await;
    let exchange = exchange_of(&delivered);
    long_strings(&delivered.json(), &mut returned);
    let seeded_path = send(
        address,
        &get(
            &format!("/v1/inboxes/{PATH_CANARY}"),
            &bearer(&harness.recipient_credential),
        ),
    )
    .await;
    assert_eq!(seeded_path.status, 422);
    assert_eq!(
        accept(address, &harness, &exchange, "idem_accept0000000001")
            .await
            .status,
        200
    );
    let document = format!("/v1/exchanges/{exchange}/document");
    let read = send(
        address,
        &get(&document, &bearer(&harness.recipient_credential)),
    )
    .await;
    assert_eq!(read.status, 200);
    let inbox = send(
        address,
        &get(
            &format!("/v1/inboxes/{RECIPIENT}"),
            &bearer(&harness.recipient_credential),
        ),
    )
    .await;
    assert_eq!(inbox.status, 200);
    let unauthorized = send(
        address,
        &get(&document, &bearer(&harness.unrelated_credential)),
    )
    .await;
    assert_eq!(unauthorized.status, 403);
    let counters = send(
        address,
        &get(
            "/operations/counters",
            &bearer(&harness.operator_credential),
        ),
    )
    .await;
    assert_eq!(counters.status, 200);

    let status = Command::new("kill")
        .args(["-s", "TERM", &child.id().to_string()])
        .status()
        .expect("kill utility");
    assert!(status.success());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("process status") {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "process did not exit"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let stdout = stdout.join().expect("stdout");
    let stderr = stderr.join().expect("stderr");
    assert_eq!(status.code(), Some(0), "{stderr}");

    let records: Vec<Value> = stdout.lines().map(closed_record).collect();
    for (operation, outcome) in [
        ("send-copy", "ok"),
        ("accept", "ok"),
        ("read-document", "ok"),
        ("list-inbox", "ok"),
        ("read-document", "forbidden"),
        ("read-counters", "ok"),
    ] {
        assert!(
            records.iter().any(|record| record["record"] == "request"
                && record["operation"] == operation
                && record["outcome"] == outcome),
            "{operation}/{outcome}: {stdout}"
        );
    }
    // Standard error holds exactly the sweep report line, as before.
    let human: Vec<&str> = stderr.lines().collect();
    assert_eq!(human.len(), 1, "{stderr}");
    assert!(human[0].starts_with("docchain-server: "), "{stderr}");
    let mut values = prohibited(&harness, &returned);
    values.extend(
        ["db.statement", "INSERT", "SELECT", "sqlx"]
            .into_iter()
            .map(str::to_owned),
    );
    values.push(exchange);
    let (_, root) = harness.fixture_location();
    values.push(root.display().to_string());
    assert_excludes(&format!("{stdout}\n{stderr}"), &values);
}

/// Reads `dropped_records` as the operator, asserting the read succeeds.
async fn dropped_records(address: SocketAddr, harness: &DemoHarness) -> u64 {
    let reply = send(
        address,
        &get(
            "/operations/counters",
            &bearer(&harness.operator_credential),
        ),
    )
    .await;
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    reply.json()["dropped_records"]
        .as_u64()
        .expect("dropped_records")
}

#[tokio::test]
async fn a_closed_standard_output_counts_lost_records_and_keeps_serving() {
    let harness = DemoHarness::new().await.expect("harness");
    let address = free_address();
    let mut child = spawn(&harness.server_environment(), address);
    let stderr = drain(child.stderr.take());
    // Standard output stays unread until ready; the pipe holds far more than readiness writes.
    let started = Instant::now();
    while ready(address).await != Some(204) {
        assert!(
            matches!(child.try_wait(), Ok(None)),
            "server exited before ready"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "server not ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(dropped_records(address, &harness).await, 0);

    // The test holds the only read end, so closing it leaves every later write refused.
    drop(child.stdout.take());
    for _ in 0..3 {
        assert_eq!(send(address, &get("/health/live", "")).await.status, 204);
    }
    let started = Instant::now();
    let dropped = loop {
        let dropped = dropped_records(address, &harness).await;
        if dropped > 0 {
            break dropped;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "refused writes were never counted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(send(address, &get("/health/live", "")).await.status, 204);
    assert!(dropped_records(address, &harness).await >= dropped);

    let status = Command::new("kill")
        .args(["-s", "TERM", &child.id().to_string()])
        .status()
        .expect("kill utility");
    assert!(status.success());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("process status") {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "process did not exit"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let stderr = stderr.join().expect("stderr");
    assert_eq!(status.code(), Some(0), "{stderr}");
    // Standard error holds exactly the sweep report line: no panic line.
    let human: Vec<&str> = stderr.lines().collect();
    assert_eq!(human.len(), 1, "{stderr}");
    assert!(human[0].starts_with("docchain-server: "), "{stderr}");
}
