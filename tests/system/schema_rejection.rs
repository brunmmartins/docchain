mod support;

#[tokio::test]
async fn rejects_invalid_document_before_commit() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let invalid_documents: [&[u8]; 4] = [
        br#"{"applicationReference":"SYN-APP0001"}"#,
        br#"{
            "applicationReference":"SYN-APP0001",
            "serviceCode":"synthetic-record-copy",
            "submittedOn":"2026-02-29",
            "statement":"Invented statement.",
            "declarations":[]
        }"#,
        br#"{
            "applicationReference":"SYN-APP0001",
            "serviceCode":"synthetic-record-copy",
            "submittedOn":"2026-09-19",
            "statement":"Invented statement.",
            "declarations":[],
            "unexpected":true
        }"#,
        br#"{"statement":"first","statement":"second"}"#,
    ];

    for document in invalid_documents {
        let mut request = support::valid_request();
        request.document = document.to_vec();
        let error = harness
            .send_copy(&sender, request)
            .await
            .expect_err("schema-invalid document");
        assert_eq!(error.category(), "invalid-document");
    }
    let stats = harness.stats().await.expect("state counts");
    assert_eq!((stats.events, stats.objects, stats.delivered), (0, 0, 0));
}
