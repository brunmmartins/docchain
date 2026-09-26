mod support;

use std::io::{Read as _, Write as _};

use docchain_domain::{DocumentId, IdempotencyKey, RequestNonce};
use docchain_server::{HttpConfig, router};

const PLAINTEXT: &[u8] = b"Please provide";

fn reveals_plaintext(bytes: &[u8]) -> bool {
    bytes
        .windows(PLAINTEXT.len())
        .any(|window| window == PLAINTEXT)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denies_unrelated_wallet_and_operator() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    let unrelated = harness
        .actor(&harness.unrelated_credential)
        .await
        .expect("verified unrelated wallet");
    let operator = harness
        .actor(&harness.operator_credential)
        .await
        .expect("verified ordinary operator");

    let recipient_wallet = support::wallet(support::RECIPIENT);
    let mut failures = Vec::new();
    for actor in [&unrelated, &operator] {
        failures.push(
            harness
                .list_inbox(actor, &recipient_wallet)
                .await
                .expect_err("inbox of another wallet"),
        );
        failures.push(
            harness
                .read_document(actor, &delivered.exchange_id)
                .await
                .expect_err("decrypt without being a participant"),
        );
    }
    for failure in &failures {
        assert_eq!(failure.category(), "forbidden");
        let diagnostics = format!("{failure:?} {failure}");
        assert!(!reveals_plaintext(diagnostics.as_bytes()), "{diagnostics}");
    }

    // The same denials hold at the HTTP boundary, and no response carries plaintext.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let application = router(harness.service(), HttpConfig::default());
    let server = tokio::spawn(async move { axum::serve(listener, application).await });
    let exchange = delivered.exchange_id.to_string();
    let credentials = [
        harness.unrelated_credential.clone(),
        harness.operator_credential.clone(),
    ];
    let responses = tokio::task::spawn_blocking(move || {
        let mut responses = Vec::new();
        for credential in &credentials {
            for path in [
                format!("/v1/exchanges/{exchange}/document"),
                format!("/v1/inboxes/{}", support::RECIPIENT),
            ] {
                let mut stream = std::net::TcpStream::connect(address).expect("connect");
                write!(
                    stream,
                    "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nConnection: close\r\n\r\n"
                )
                .expect("request");
                let mut response = Vec::new();
                stream.read_to_end(&mut response).expect("response");
                responses.push(response);
            }
        }
        responses
    })
    .await
    .expect("HTTP client");
    server.abort();
    for response in &responses {
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(response)
        );
        assert!(!reveals_plaintext(response));
    }

    let envelope = harness
        .envelope(&delivered.exchange_id)
        .await
        .expect("ciphertext envelope");
    let events = harness.audit_events().await.expect("audit events");
    assert!(!reveals_plaintext(&envelope));
    assert!(
        events
            .iter()
            .all(|event| !reveals_plaintext(format!("{event:?}").as_bytes()))
    );
}

/// A wallet probing another sender's document tuple gets the same answer, and causes the same
/// absence of writes, whether or not that tuple was delivered.
#[tokio::test]
async fn unrelated_wallet_cannot_probe_another_senders_tuple() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery of the probed tuple");
    let before = harness.stats().await.expect("state counts");
    let prober = harness
        .actor(&harness.unkeyed_credential)
        .await
        .expect("verified unkeyed wallet");

    let mut used = support::valid_request();
    used.sender = support::wallet(support::UNKEYED);
    used.request_nonce = RequestNonce::new([0x55; 16]);
    used.idempotency_key = IdempotencyKey::new("idem_0000000000000055").expect("probe key");
    let mut unused = used.clone();
    unused.document_id = DocumentId::new("doc_0000000000000077").expect("unused document id");
    unused.request_nonce = RequestNonce::new([0x56; 16]);
    unused.idempotency_key = IdempotencyKey::new("idem_0000000000000056").expect("probe key");

    let used = harness
        .send_copy(&prober, used)
        .await
        .expect_err("probe of a delivered tuple");
    let unused = harness
        .send_copy(&prober, unused)
        .await
        .expect_err("probe of an unused tuple");
    assert_eq!(used.category(), unused.category());
    assert_ne!(used.category(), "replay");
    assert_eq!(format!("{used}"), format!("{unused}"));
    let after = harness.stats().await.expect("state counts");
    assert_eq!(
        (after.delivered, after.events, after.objects),
        (before.delivered, before.events, before.objects)
    );
}
