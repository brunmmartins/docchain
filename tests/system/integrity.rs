mod support;

use docchain_domain::IdempotencyKey;
use docchain_server::DemoHarness;

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
        assert_eq!(
            tampered
                .verify_audit(None)
                .await
                .expect_err(case)
                .category(),
            "integrity-failure",
            "{case}"
        );
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
    assert_eq!(
        harness
            .verify_audit(None)
            .await
            .expect_err("changed envelope")
            .category(),
        "integrity-failure"
    );
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
        for replica in [false, true] {
            for statement in [
                format!("UPDATE {table} SET {update_column}"),
                format!("DELETE FROM {table}"),
                format!("TRUNCATE {table} CASCADE"),
            ] {
                assert_eq!(
                    harness.sqlstate_of(&statement, replica).await,
                    Err("23001".to_owned()),
                    "{statement} (replica: {replica})"
                );
            }
        }
    }

    let mut after = Vec::new();
    for table in tables {
        after.push(count(table).await);
    }
    assert_eq!(before, after);
}
