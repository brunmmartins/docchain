mod support;

use docchain_application::Limits;
use docchain_domain::{DocumentId, DocumentVersion, IdempotencyKey, RequestNonce};
use docchain_server::DemoHarness;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_replay_without_duplicate_credit() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let request = support::valid_request();
    // Identical sends race on separate worker threads; exactly one commits and both get its result.
    let racers = (0..4)
        .map(|_| {
            let service = harness.service();
            let (actor, command) = (sender.clone(), request.clone());
            tokio::spawn(async move { service.send_copy(&actor, command).await })
        })
        .collect::<Vec<_>>();
    let mut results = Vec::new();
    for racer in racers {
        results.push(
            racer
                .await
                .expect("racing task")
                .expect("idempotent delivery"),
        );
    }
    let first = results[0].clone();
    assert!(results.iter().all(|result| *result == first));
    let raced = harness.stats().await.expect("state counts");
    assert_eq!((raced.delivered, raced.events, raced.objects), (1, 1, 1));

    let mut changed_content = request.clone();
    changed_content.document = br#"{
        "applicationReference":"SYN-APP0001",
        "serviceCode":"synthetic-record-copy",
        "submittedOn":"2026-09-19",
        "statement":"Different invented statement.",
        "declarations":[]
    }"#
    .to_vec();
    assert_eq!(
        harness
            .send_copy(&sender, changed_content)
            .await
            .expect_err("same key different content")
            .category(),
        "replay"
    );

    let mut same_nonce = support::valid_request();
    same_nonce.document_id = DocumentId::new("doc_0000000000000002").expect("second document id");
    same_nonce.idempotency_key =
        IdempotencyKey::new("idem_0000000000000002").expect("second idempotency key");
    assert_eq!(
        harness
            .send_copy(&sender, same_nonce)
            .await
            .expect_err("nonce replay")
            .category(),
        "replay"
    );

    let mut same_version_tuple = support::valid_request();
    same_version_tuple.request_nonce = RequestNonce::new([0x11; 16]);
    same_version_tuple.idempotency_key =
        IdempotencyKey::new("idem_0000000000000003").expect("third idempotency key");
    assert_eq!(
        harness
            .send_copy(&sender, same_version_tuple)
            .await
            .expect_err("document-version-recipient replay")
            .category(),
        "replay"
    );

    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");
    let accept_one = IdempotencyKey::new("idem_accept0000000001").expect("acceptance key");
    let accept_two = IdempotencyKey::new("idem_accept0000000002").expect("acceptance key");
    let (first_accept, concurrent_accept) = tokio::join!(
        harness.accept(&recipient, &first.exchange_id, &accept_one),
        harness.accept(&recipient, &first.exchange_id, &accept_two)
    );
    let first_accept = first_accept.expect("first acceptance");
    let concurrent_accept = concurrent_accept.expect("concurrent acceptance replay");
    assert_eq!(first_accept, concurrent_accept);

    let replay_accept = harness
        .accept(
            &recipient,
            &first.exchange_id,
            &IdempotencyKey::new("idem_accept0000000003").expect("acceptance key"),
        )
        .await
        .expect("later acceptance replay");
    assert_eq!(first_accept, replay_accept);

    // An acceptance key the recipient already spent cannot accept a different exchange.
    let mut second = support::valid_request();
    second.document_id = DocumentId::new("doc_0000000000000009").expect("ninth document");
    second.request_nonce = RequestNonce::new([0x33; 16]);
    second.idempotency_key = IdempotencyKey::new("idem_0000000000000009").expect("ninth key");
    let second = harness
        .send_copy(&sender, second)
        .await
        .expect("second delivery");
    let spent = if harness
        .execute_unchecked(
            "SELECT 1 FROM acceptances WHERE idempotency_key = 'idem_accept0000000001'",
        )
        .await
        .expect("acceptance key lookup")
        == 1
    {
        &accept_one
    } else {
        &accept_two
    };
    assert_eq!(
        harness
            .accept(&recipient, &second.exchange_id, spent)
            .await
            .expect_err("reused acceptance key")
            .category(),
        "replay"
    );

    let stats = harness.stats().await.expect("state counts");
    assert_eq!(
        (
            stats.events,
            stats.objects,
            stats.credits,
            stats.credit_entries
        ),
        (3, 2, 1, 2)
    );

    let bounded = DemoHarness::new_with_limits(Limits {
        pending_per_relationship: 1,
        ..Limits::default()
    })
    .await
    .expect("bounded harness");
    let bounded_sender = support::sender(&bounded).await;
    bounded
        .send_copy(&bounded_sender, support::valid_request())
        .await
        .expect("first pending delivery");
    let mut second = support::valid_request();
    second.document_id = DocumentId::new("doc_0000000000000002").expect("second document");
    second.document_version = DocumentVersion::new(2).expect("second version");
    second.request_nonce = RequestNonce::new([0x22; 16]);
    second.idempotency_key = IdempotencyKey::new("idem_0000000000000004").expect("fourth key");
    assert_eq!(
        bounded
            .send_copy(&bounded_sender, second)
            .await
            .expect_err("pending relationship bound")
            .category(),
        "pending-limit"
    );
}

/// Two senders may deliver the same document ID, version, and recipient; each sender's own
/// replay of that tuple is still refused, and neither sender can block the other.
#[tokio::test]
async fn document_tuple_is_scoped_to_the_sender() {
    let harness = support::harness().await;
    let first = support::sender(&harness).await;
    let third = harness
        .actor(&harness.unrelated_credential)
        .await
        .expect("verified third wallet");

    let first_request = support::valid_request();
    let mut third_request = support::valid_request();
    third_request.sender = support::wallet(support::THIRD);
    let first_delivery = harness
        .send_copy(&first, first_request.clone())
        .await
        .expect("first sender delivers the tuple");
    // The same tuple, nonce, and idempotency key under another sender are that sender's own.
    let third_delivery = harness
        .send_copy(&third, third_request.clone())
        .await
        .expect("a keyed second sender is not blocked by the first sender's tuple");
    assert_ne!(first_delivery.exchange_id, third_delivery.exchange_id);

    for (actor, request) in [(&first, first_request), (&third, third_request)] {
        let mut replay = request;
        replay.request_nonce = RequestNonce::new([0x44; 16]);
        replay.idempotency_key =
            IdempotencyKey::new("idem_0000000000000044").expect("fresh idempotency key");
        assert_eq!(
            harness
                .send_copy(actor, replay)
                .await
                .expect_err("the sender's own tuple replay")
                .category(),
            "replay"
        );
    }

    let stats = harness.stats().await.expect("state counts");
    assert_eq!((stats.delivered, stats.events, stats.objects), (2, 2, 2));
}
