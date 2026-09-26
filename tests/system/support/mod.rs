use docchain_domain::{DocumentId, DocumentVersion, IdempotencyKey, RequestNonce, WalletId};
use docchain_server::{Actor, DemoHarness, SendCopyCommand};

pub const SENDER: &str = "wal_0000000000000001";
pub const RECIPIENT: &str = "wal_0000000000000002";
/// Signs in with the harness's unrelated credential and holds its own keys.
#[allow(
    dead_code,
    reason = "each system-test target uses a different part of the support module"
)]
pub const THIRD: &str = "wal_0000000000000003";
/// Signs in with the harness's unkeyed credential and holds no keys.
#[allow(
    dead_code,
    reason = "each system-test target uses a different part of the support module"
)]
pub const UNKEYED: &str = "wal_0000000000000004";

pub async fn harness() -> DemoHarness {
    DemoHarness::new()
        .await
        .expect("supplied PostgreSQL and a writable temporary root")
}

pub fn valid_request() -> SendCopyCommand {
    SendCopyCommand {
        sender: wallet(SENDER),
        recipient: wallet(RECIPIENT),
        document_id: DocumentId::new("doc_0000000000000001").expect("fixture document id"),
        document_version: DocumentVersion::new(1).expect("fixture document version"),
        request_nonce: RequestNonce::new([
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ]),
        idempotency_key: IdempotencyKey::new("idem_0000000000000001")
            .expect("fixture idempotency key"),
        schema_id: "urn:docchain:schema:service-application:1.0.0".to_owned(),
        schema_version: "1.0.0".to_owned(),
        document: include_bytes!("../../../schemas/service-application/example.json").to_vec(),
    }
}

pub async fn sender(harness: &DemoHarness) -> Actor {
    harness
        .actor(&harness.sender_credential)
        .await
        .expect("verified sender")
}

pub fn wallet(value: &str) -> WalletId {
    WalletId::new(value).expect("fixture wallet id")
}
