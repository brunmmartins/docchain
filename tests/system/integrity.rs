mod support;

use std::net::SocketAddr;

use docchain_application::{ApplicationError, AuditMismatch};
use docchain_domain::{DocumentVersion, IdempotencyKey, RequestNonce};
use docchain_server::{DemoHarness, HttpConfig, ServiceError, router};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

const COLUMNS: &str = "kind, exchange_id, object_id, commitment, envelope_version, protected_hash, \
    sender_wallet, recipient_wallet, document_id, document_version, registry_sequence, \
    committed_at, previous_hash, event_hash, signature";

/// A harness holding one delivered and one accepted event, and its exchange ID.
async fn exchanged() -> (DemoHarness, docchain_domain::ExchangeId) {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");
    harness
        .accept(
            &recipient,
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");
    (harness, delivered.exchange_id)
}

#[tokio::test]
async fn verifies_chain_without_plaintext() {
    let (harness, exchange) = exchanged().await;
    let verified = harness.verify_audit(None).await.expect("verified chain");
    let checkpoint = verified.head.expect("signed checkpoint");
    assert_eq!((verified.event_count, checkpoint.sequence), (2, 2));
    assert!(
        !format!("{verified:?}").contains("Please provide"),
        "audit report carries no plaintext"
    );
    let events = harness.audit_events().await.expect("audit events");
    assert!(events.iter().all(|event| {
        !format!("{event:?}")
            .as_bytes()
            .windows(b"Please provide".len())
            .any(|window| window == b"Please provide")
    }));

    // A holder of the earlier head still verifies an intact chain.
    assert_eq!(
        harness
            .verify_audit(Some(checkpoint))
            .await
            .expect("intact chain against held head")
            .event_count,
        2
    );

    // The table owner, who can switch off the append-only refusal, still cannot change, add,
    // drop, or reorder events without the audit key noticing.
    let tampering = [
        (
            "alteration",
            "UPDATE audit_events SET registry_sequence = registry_sequence + 1 WHERE sequence = 1"
                .to_owned(),
        ),
        (
            "commit time alteration",
            "UPDATE audit_events SET committed_at = committed_at + 1 WHERE sequence = 1".to_owned(),
        ),
        (
            "insertion",
            format!(
                "INSERT INTO audit_events (sequence, {COLUMNS}) \
                 SELECT 3, {COLUMNS} FROM audit_events WHERE sequence = 2"
            ),
        ),
        (
            "removal",
            "DELETE FROM audit_events WHERE sequence = 1".to_owned(),
        ),
        (
            "reordering",
            "UPDATE audit_events SET sequence = -sequence; \
             UPDATE audit_events SET sequence = CASE sequence WHEN -1 THEN 2 ELSE 1 END"
                .to_owned(),
        ),
    ];
    for (case, statement) in tampering {
        let (tampered, _) = exchanged().await;
        assert!(
            tampered
                .tamper_as_owner(&statement)
                .await
                .expect("tamper with events")
                > 0,
            "{case}"
        );
        let error = tampered.verify_audit(None).await.expect_err(case);
        assert_eq!(error.category(), "integrity-failure", "{case}");
        assert_eq!(reason(&error), Some(AuditMismatch::EventChain), "{case}");
    }

    // Dropping the newest event leaves a valid prefix, which only the held head exposes.
    let (truncated, _) = exchanged().await;
    let held = truncated
        .verify_audit(None)
        .await
        .expect("checkpoint")
        .head
        .expect("head");
    truncated
        .truncate_last_event()
        .await
        .expect("truncate event");
    assert_eq!(
        truncated
            .verify_audit(Some(held))
            .await
            .expect_err("tail truncation")
            .category(),
        "integrity-failure"
    );

    // The chain also commits to the exact stored ciphertext.
    harness
        .alter_envelope(&exchange)
        .await
        .expect("alter envelope");
    let error = harness
        .verify_audit(None)
        .await
        .expect_err("changed envelope");
    assert_eq!(error.category(), "integrity-failure");
    assert_eq!(reason(&error), Some(AuditMismatch::EnvelopeCommitment));
}

/// The class of check an audit verification failure names.
fn reason(error: &ServiceError) -> Option<AuditMismatch> {
    match error {
        ServiceError::Application(ApplicationError::AuditMismatch(mismatch)) => Some(*mismatch),
        _ => None,
    }
}

#[tokio::test]
async fn append_only_tables_refuse_update_delete_and_truncate() {
    let (harness, _) = exchanged().await;
    let tables = [
        "audit_events",
        "acceptances",
        "credit_transactions",
        "credit_entries",
    ];
    let count = |table: &'static str| {
        let harness = &harness;
        async move {
            harness
                .sqlstate_of(&format!("SELECT 1 FROM {table}"), false)
                .await
                .expect("count rows")
        }
    };
    let mut before = Vec::new();
    for table in tables {
        before.push(count(table).await);
    }
    assert!(before.iter().all(|rows| *rows > 0), "{before:?}");

    for table in tables {
        let update_column = match table {
            "audit_events" => "registry_sequence = registry_sequence",
            "acceptances" => "exchange_id = exchange_id",
            _ => "eligibility_key = eligibility_key",
        };
        for statement in [
            format!("UPDATE {table} SET {update_column}"),
            format!("DELETE FROM {table}"),
            format!("TRUNCATE {table} CASCADE"),
        ] {
            assert_eq!(
                harness.sqlstate_of(&statement, false).await,
                Err("23001".to_owned()),
                "{statement}"
            );
            // The owner is not a superuser, so it cannot enter replica mode at all; no
            // statement runs in replica mode.
            assert_eq!(
                harness.sqlstate_of(&statement, true).await,
                Err("42501".to_owned()),
                "{statement} (replica)"
            );
        }
    }
    // Every trigger fires whatever the session replication role, the balance triggers too.
    let triggers: Vec<(String, String)> = sqlx::query_as(
        "SELECT trigger_row.tgname::text, trigger_row.tgenabled::text \
         FROM pg_trigger AS trigger_row \
         JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid \
         WHERE relation.relnamespace = current_schema()::regnamespace \
             AND NOT trigger_row.tgisinternal ORDER BY 1",
    )
    .fetch_all(harness.owner_pool())
    .await
    .expect("triggers");
    for balance in ["credit_entries_balanced", "credit_transactions_balanced"] {
        assert!(
            triggers.iter().any(|(name, _)| name == balance),
            "{balance}"
        );
    }
    assert!(
        triggers.iter().all(|(_, enabled)| enabled == "A"),
        "{triggers:?}"
    );

    let mut after = Vec::new();
    for table in tables {
        after.push(count(table).await);
    }
    assert_eq!(before, after);
}

/// Serves this harness's service on a loopback port until the sender is dropped.
async fn serve(harness: &DemoHarness) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback port");
    let address = listener.local_addr().expect("loopback address");
    let (stop, stopped) = oneshot::channel::<()>();
    let application = router(harness.service(), HttpConfig::default());
    tokio::spawn(docchain_server::serve::serve_until(
        listener,
        application,
        async move {
            let _ = stopped.await;
        },
        std::time::Duration::from_secs(5),
    ));
    (address, stop)
}

/// `GET /v1/audit/verify` as the auditor: the status and the raw body.
async fn verify_over_http(harness: &DemoHarness, address: SocketAddr) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "GET /v1/audit/verify HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {}\r\nConnection: close\r\n\r\n",
        harness.auditor_credential
    );
    stream.write_all(request.as_bytes()).await.expect("request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("response");
    let status = std::str::from_utf8(&response[9..12])
        .expect("status")
        .parse()
        .expect("status code");
    let body_start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header end")
        + 4;
    (status, response[body_start..].to_vec())
}

/// Whether `haystack` holds `needle` anywhere.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A second delivery from the sender to the recipient, never accepted.
async fn deliver_second(harness: &DemoHarness) -> docchain_domain::ExchangeId {
    let mut request = support::valid_request();
    request.document_version = DocumentVersion::new(2).expect("version");
    request.request_nonce = RequestNonce::new([0x11; 16]);
    request.idempotency_key = IdempotencyKey::new("idem_0000000000000002").expect("key");
    harness
        .send_copy(&support::sender(harness).await, request)
        .await
        .expect("second delivery")
        .exchange_id
}

#[tokio::test]
async fn reconciles_credits_with_acceptances() {
    // No acceptance: nothing to reconcile, and the ledger is empty.
    let unaccepted = support::harness().await;
    unaccepted
        .send_copy(
            &support::sender(&unaccepted).await,
            support::valid_request(),
        )
        .await
        .expect("delivery");
    let report = unaccepted.verify_audit(None).await.expect("verified");
    assert_eq!(
        (
            report.credits.accepted_exchanges(),
            report.credits.credit_transactions()
        ),
        (0, 0)
    );

    // Two deliveries and one acceptance.
    let (harness, accepted) = exchanged().await;
    let pending = deliver_second(&harness).await;
    let report = harness.verify_audit(None).await.expect("verified");
    assert_eq!(report.event_count, 3);
    assert_eq!(
        (
            report.credits.accepted_exchanges(),
            report.credits.credit_transactions()
        ),
        (1, 1)
    );

    let (address, _stop) = serve(&harness).await;
    let (status, body) = verify_over_http(&harness, address).await;
    assert_eq!(status, 200);
    let json: Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(
        json["credits"],
        json!({"reconciled": true, "accepted_exchanges": 1, "credit_transactions": 1})
    );
    for secret in [
        b"Please provide".as_slice(),
        b"SYN-APP0001",
        accepted.as_str().as_bytes(),
        pending.as_str().as_bytes(),
        support::SENDER.as_bytes(),
    ] {
        assert!(!contains(&body, secret));
    }
}

#[tokio::test]
async fn detects_credit_ledger_tampering() {
    // Each case tampers, as the migration owner, with a fresh schema that holds one accepted
    // exchange and one delivered, unaccepted exchange.
    let cases: [(&str, &str, AuditMismatch); 4] = [
        (
            "balanced credit for an unaccepted exchange",
            "INSERT INTO credit_transactions VALUES ('acceptance:' || '{pending}', '{pending}'); \
             INSERT INTO credit_entries VALUES \
                 ('acceptance:' || '{pending}', 'issuance', -1), \
                 ('acceptance:' || '{pending}', '{sender}', 1)",
            AuditMismatch::CreditUnaccepted,
        ),
        (
            "second transaction for one acceptance",
            "ALTER TABLE credit_transactions \
                 DROP CONSTRAINT credit_transactions_exchange_id_key; \
             INSERT INTO credit_transactions VALUES ('acceptance:second', '{accepted}'); \
             INSERT INTO credit_entries VALUES \
                 ('acceptance:second', 'issuance', -1), ('acceptance:second', '{sender}', 1)",
            AuditMismatch::CreditDuplicate,
        ),
        (
            "credited account changed",
            "UPDATE",
            AuditMismatch::CreditUnbalanced,
        ),
        (
            "balanced transaction removed",
            "DELETE",
            AuditMismatch::CreditMissing,
        ),
    ];
    for (case, statement, expected) in cases {
        let (harness, accepted) = exchanged().await;
        let pending = deliver_second(&harness).await;
        assert!(harness.verify_audit(None).await.is_ok(), "{case}: before");
        match statement {
            "UPDATE" => {
                assert_eq!(
                    harness
                        .sqlstate_as_owner(
                            "credit_entries",
                            &format!(
                                "UPDATE credit_entries SET account_id = '{}' WHERE amount = 1",
                                support::THIRD
                            ),
                        )
                        .await,
                    Ok(1),
                    "{case}"
                );
            }
            "DELETE" => {
                harness
                    .execute_unchecked(
                        "ALTER TABLE credit_entries \
                             DISABLE TRIGGER credit_entries_refuse_update_delete; \
                         ALTER TABLE credit_transactions \
                             DISABLE TRIGGER credit_transactions_refuse_update_delete; \
                         DELETE FROM credit_entries; DELETE FROM credit_transactions",
                    )
                    .await
                    .expect(case);
                // Pending deferred trigger events forbid re-enabling in the same transaction.
                harness
                    .execute_unchecked(
                        "ALTER TABLE credit_entries \
                             ENABLE ALWAYS TRIGGER credit_entries_refuse_update_delete; \
                         ALTER TABLE credit_transactions \
                             ENABLE ALWAYS TRIGGER credit_transactions_refuse_update_delete",
                    )
                    .await
                    .expect(case);
            }
            statement => {
                harness
                    .execute_unchecked(
                        &statement
                            .replace("{pending}", pending.as_str())
                            .replace("{accepted}", accepted.as_str())
                            .replace("{sender}", support::SENDER),
                    )
                    .await
                    .expect(case);
            }
        }
        assert_eq!(
            reason(&harness.verify_audit(None).await.expect_err(case)),
            Some(expected),
            "{case}"
        );

        let (address, _stop) = serve(&harness).await;
        let (status, body) = verify_over_http(&harness, address).await;
        assert_eq!(status, 409, "{case}");
        let json: Value = serde_json::from_slice(&body).expect("JSON body");
        assert_eq!(
            json,
            json!({"category": "integrity-failure", "reason": expected.as_str()}),
            "{case}"
        );
        for secret in [
            b"Please provide".as_slice(),
            accepted.as_str().as_bytes(),
            pending.as_str().as_bytes(),
            support::SENDER.as_bytes(),
        ] {
            assert!(!contains(&body, secret), "{case}");
        }
    }
}
