mod support;

use std::time::{SystemTime, UNIX_EPOCH};

use docchain_domain::{EventKind, IdempotencyKey, parse_document, sha256};
use docchain_server::DemoHarness;

#[tokio::test]
async fn delivers_valid_service_application() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("valid send-copy");
    let stats = harness.stats().await.expect("state counts");

    assert_eq!(stats.delivered, 1);
    assert_eq!(stats.events, 1);
    assert_eq!(stats.objects, 1);
    assert!(harness.object_exists(&delivered.object_id).await);
    let envelope = harness
        .envelope(&delivered.exchange_id)
        .await
        .expect("stored envelope");
    assert_eq!(sha256(&envelope), delivered.envelope_commitment);
    assert_ne!(envelope, support::valid_request().document);

    let expected = parse_document(&support::valid_request().document)
        .expect("fixture document")
        .bytes()
        .to_vec();
    let sender_copy = harness
        .read_document(&sender, &delivered.exchange_id)
        .await
        .expect("sender copy");
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");
    let recipient_copy = harness
        .read_document(&recipient, &delivered.exchange_id)
        .await
        .expect("recipient copy");
    assert_eq!(sender_copy, expected);
    assert_eq!(recipient_copy, expected);

    let events = harness.audit_events().await.expect("delivery event");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].draft.kind, EventKind::Delivered);
    assert_eq!(
        events[0].draft.envelope_commitment,
        delivered.envelope_commitment
    );
    assert_eq!(events[0].draft.object_id, delivered.object_id);
    assert!(
        !format!("{:?}", events[0])
            .as_bytes()
            .windows(b"Please provide".len())
            .any(|window| window == b"Please provide")
    );
}

/// The third wallet's ID sorts after the recipient's, so the sender is the second protected
/// recipient; both parties must still open the envelope, and acceptance must follow.
#[tokio::test]
async fn delivers_when_the_sender_sorts_second() {
    let harness = support::harness().await;
    let third = harness
        .actor(&harness.unrelated_credential)
        .await
        .expect("verified third wallet");
    let mut request = support::valid_request();
    request.sender = support::wallet(support::THIRD);
    assert!(support::RECIPIENT.as_bytes() < support::THIRD.as_bytes());
    let delivered = harness
        .send_copy(&third, request.clone())
        .await
        .expect("delivery from a sender that sorts second");

    let expected = parse_document(&request.document)
        .expect("fixture document")
        .bytes()
        .to_vec();
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");
    assert_eq!(
        harness
            .read_document(&third, &delivered.exchange_id)
            .await
            .expect("sender copy"),
        expected
    );
    assert_eq!(
        harness
            .read_document(&recipient, &delivered.exchange_id)
            .await
            .expect("recipient copy"),
        expected
    );

    let accepted = harness
        .accept(
            &recipient,
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");
    assert_eq!(accepted.exchange_id, delivered.exchange_id);
    let stats = harness.stats().await.expect("state counts");
    assert_eq!(
        (
            stats.delivered,
            stats.events,
            stats.credits,
            stats.credit_entries
        ),
        (1, 2, 1, 2)
    );
}

fn unix_now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();
    i64::try_from(seconds).expect("seconds fit")
}

/// The registry already holds a revocation of the recipient's encryption key that takes effect
/// in 2099. A copy sent before then is delivered, accepted, and readable by both parties,
/// because reads judge the keys at the send's recorded commit time.
#[tokio::test]
async fn delivers_and_reads_before_a_scheduled_revocation() {
    let harness = DemoHarness::with_scheduled_revocation()
        .await
        .expect("supplied PostgreSQL and a writable temporary root");
    let sender = support::sender(&harness).await;
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");
    let started = unix_now();
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery before the revocation takes effect");
    let finished = unix_now();
    harness
        .accept(
            &recipient,
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");
    let stats = harness.stats().await.expect("state counts");
    assert_eq!((stats.delivered, stats.events, stats.credits), (1, 2, 1));

    let expected = parse_document(&support::valid_request().document)
        .expect("fixture document")
        .bytes()
        .to_vec();
    for reader in [&sender, &recipient] {
        assert_eq!(
            harness
                .read_document(reader, &delivered.exchange_id)
                .await
                .expect("the recipient key was in force at the send"),
            expected
        );
    }

    let events = harness.audit_events().await.expect("audit events");
    let committed_at = events[0].draft.committed_at.unix_seconds();
    assert!(
        (started..=finished).contains(&committed_at),
        "{committed_at} outside {started}..={finished}"
    );
    assert!(
        events
            .iter()
            .all(|event| event.draft.committed_at.unix_seconds() == committed_at)
    );
    assert_eq!(
        harness
            .execute_unchecked(&format!(
                "SELECT 1 FROM exchanges WHERE exchange_id = '{}' AND committed_at = {committed_at}",
                delivered.exchange_id
            ))
            .await
            .expect("exchange commit time"),
        1
    );
}
