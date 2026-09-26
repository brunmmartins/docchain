//! Versioned HTTP adapter for the first private exchange.

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        HeaderMap, StatusCode, Uri,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use docchain_application::{Actor, ApplicationError, Credential, SendCopyCommand};
use docchain_domain::{
    Checkpoint, DocumentId, DocumentVersion, ExchangeId, IdempotencyKey, MAX_DOCUMENT_BYTES,
    RequestNonce, WalletId, canonicalize, parse_document,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{sync::Semaphore, time};

use crate::{DocchainService, ServiceError};

/// Limits applied at the untrusted HTTP boundary.
#[derive(Clone, Copy, Debug)]
pub struct HttpConfig {
    /// Deadline for one request.
    pub request_timeout: Duration,
    /// Maximum number of requests admitted before body extraction.
    pub max_in_flight: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            max_in_flight: 64,
        }
    }
}

#[derive(Clone)]
struct HttpState {
    service: Arc<DocchainService>,
}

#[derive(Clone)]
struct Gate {
    deadline: Duration,
    permits: Arc<Semaphore>,
}

/// Builds the version 1 API around the fully composed service.
///
/// Admission and the end-to-end deadline run before body extraction. Every business handler
/// authenticates a credential through the identity port before invoking a use case.
pub fn router(service: Arc<DocchainService>, config: HttpConfig) -> Router {
    let state = HttpState { service };
    let gate = Gate {
        deadline: config.request_timeout,
        permits: Arc::new(Semaphore::new(config.max_in_flight)),
    };
    let business = Router::new()
        .route("/v1/send-copies", post(send_copy))
        .route("/v1/exchanges/{exchange_id}/acceptances", post(accept))
        .route("/v1/exchanges/{exchange_id}/document", get(read_document))
        .route("/v1/inboxes/{wallet_id}", get(list_inbox))
        .route("/v1/audit/verify", get(verify_audit))
        .layer(DefaultBodyLimit::max(MAX_DOCUMENT_BYTES))
        .layer(middleware::from_fn_with_state(gate, admission));
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .merge(business)
        .with_state(state)
}

async fn admission(State(gate): State<Gate>, request: Request, next: Next) -> Response {
    let Ok(permit) = gate.permits.try_acquire_owned() else {
        return ApiError::Overloaded.into_response();
    };
    let response = time::timeout(gate.deadline, async move {
        #[cfg(test)]
        if request.headers().contains_key("x-docchain-test-delay") {
            time::sleep(Duration::from_millis(10)).await;
        }
        next.run(request).await
    })
    .await;
    drop(permit);
    response.unwrap_or_else(|_| ApiError::Timeout.into_response())
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<HttpState>) -> StatusCode {
    match state.service.ready().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendCopyDto {
    sender: String,
    recipient: String,
    document_id: String,
    document_version: u64,
    request_nonce: String,
    idempotency_key: String,
    schema_id: String,
    schema_version: String,
    document: Value,
}

#[derive(Serialize)]
struct DeliveryDto {
    exchange_id: String,
    object_id: String,
    envelope_commitment: String,
}

async fn send_copy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<DeliveryDto>), ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let strict = parse_document(&body).map_err(|_| ApiError::InvalidRequest)?;
    let dto: SendCopyDto =
        serde_json::from_value(strict.value().clone()).map_err(|_| ApiError::InvalidRequest)?;
    let request_nonce: [u8; 16] = strict_b64(&dto.request_nonce)?
        .try_into()
        .map_err(|_| ApiError::InvalidRequest)?;
    let command = SendCopyCommand {
        sender: WalletId::new(dto.sender).map_err(|_| ApiError::InvalidRequest)?,
        recipient: WalletId::new(dto.recipient).map_err(|_| ApiError::InvalidRequest)?,
        document_id: DocumentId::new(dto.document_id).map_err(|_| ApiError::InvalidRequest)?,
        document_version: DocumentVersion::new(dto.document_version)
            .map_err(|_| ApiError::InvalidRequest)?,
        request_nonce: RequestNonce::new(request_nonce),
        idempotency_key: IdempotencyKey::new(dto.idempotency_key)
            .map_err(|_| ApiError::InvalidRequest)?,
        schema_id: dto.schema_id,
        schema_version: dto.schema_version,
        document: canonicalize(&dto.document).map_err(|_| ApiError::InvalidRequest)?,
    };
    let delivered = state.service.send_copy(&actor, command).await?;
    Ok((
        StatusCode::CREATED,
        Json(DeliveryDto {
            exchange_id: delivered.exchange_id.to_string(),
            object_id: delivered.object_id.to_string(),
            envelope_commitment: URL_SAFE_NO_PAD.encode(delivered.envelope_commitment),
        }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceDto {
    idempotency_key: String,
}

#[derive(Serialize)]
struct AcceptanceDtoOut {
    exchange_id: String,
    credit_awarded: i64,
}

async fn accept(
    State(state): State<HttpState>,
    Path(exchange_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AcceptanceDtoOut>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let exchange_id = ExchangeId::new(exchange_id).map_err(|_| ApiError::InvalidRequest)?;
    let strict = parse_document(&body).map_err(|_| ApiError::InvalidRequest)?;
    let dto: AcceptanceDto =
        serde_json::from_value(strict.value().clone()).map_err(|_| ApiError::InvalidRequest)?;
    let key = IdempotencyKey::new(dto.idempotency_key).map_err(|_| ApiError::InvalidRequest)?;
    let accepted = state.service.accept(&actor, &exchange_id, &key).await?;
    Ok(Json(AcceptanceDtoOut {
        exchange_id: accepted.exchange_id.to_string(),
        credit_awarded: accepted.credit_awarded,
    }))
}

async fn read_document(
    State(state): State<HttpState>,
    Path(exchange_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let exchange_id = ExchangeId::new(exchange_id).map_err(|_| ApiError::InvalidRequest)?;
    let document = state.service.read_document(&actor, &exchange_id).await?;
    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        document,
    )
        .into_response())
}

#[derive(Serialize)]
struct InboxDto {
    exchange_ids: Vec<String>,
}

async fn list_inbox(
    State(state): State<HttpState>,
    Path(wallet_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<InboxDto>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let wallet = WalletId::new(wallet_id).map_err(|_| ApiError::InvalidRequest)?;
    let exchange_ids = state
        .service
        .list_inbox(&actor, &wallet)
        .await?
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    Ok(Json(InboxDto { exchange_ids }))
}

#[derive(Serialize)]
struct AuditDto {
    valid: bool,
    event_count: usize,
    head: Option<CheckpointDto>,
}

/// A signed chain head. An auditor keeps the one it last verified and presents it again, so
/// removing events after it is detected.
#[derive(Serialize)]
struct CheckpointDto {
    sequence: u64,
    event_hash: String,
    signature: String,
}

async fn verify_audit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<AuditDto>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let expected = expected_head(uri.query())?;
    let report = state.service.verify_audit(&actor, expected).await?;
    Ok(Json(AuditDto {
        valid: true,
        event_count: report.event_count,
        head: report.head.map(|head| CheckpointDto {
            sequence: head.sequence,
            event_hash: URL_SAFE_NO_PAD.encode(head.event_hash),
            signature: URL_SAFE_NO_PAD.encode(head.signature),
        }),
    }))
}

/// Parses `head_sequence`, `head_event_hash`, and `head_signature`: all three or none, each
/// once, and nothing else.
fn expected_head(query: Option<&str>) -> Result<Option<Checkpoint>, ApiError> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(None);
    };
    let (mut sequence, mut event_hash, mut signature) = (None, None, None);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or(ApiError::InvalidRequest)?;
        let slot = match name {
            "head_sequence" => &mut sequence,
            "head_event_hash" => &mut event_hash,
            "head_signature" => &mut signature,
            _ => return Err(ApiError::InvalidRequest),
        };
        if slot.replace(value).is_some() {
            return Err(ApiError::InvalidRequest);
        }
    }
    let (Some(sequence), Some(event_hash), Some(signature)) = (sequence, event_hash, signature)
    else {
        return Err(ApiError::InvalidRequest);
    };
    if sequence.is_empty() || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::InvalidRequest);
    }
    Ok(Some(Checkpoint {
        sequence: sequence.parse().map_err(|_| ApiError::InvalidRequest)?,
        event_hash: strict_b64(event_hash)?
            .try_into()
            .map_err(|_| ApiError::InvalidRequest)?,
        signature: strict_b64(signature)?
            .try_into()
            .map_err(|_| ApiError::InvalidRequest)?,
    }))
}

async fn authenticate(state: &HttpState, headers: &HeaderMap) -> Result<Actor, ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(ApiError::Unauthenticated)?;
    state
        .service
        .authenticate(Credential::new(value.to_owned()))
        .await
        .map_err(ApiError::Service)
}

fn strict_b64(value: &str) -> Result<Vec<u8>, ApiError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::InvalidRequest)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ApiError::InvalidRequest);
    }
    Ok(decoded)
}

enum ApiError {
    Unauthenticated,
    InvalidRequest,
    Overloaded,
    Timeout,
    Service(ServiceError),
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}

#[derive(Serialize)]
struct Problem {
    category: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, category) = match self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::InvalidRequest => (StatusCode::UNPROCESSABLE_ENTITY, "invalid-request"),
            Self::Overloaded => (StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Self::Service(error) => service_problem(&error),
        };
        (status, Json(Problem { category })).into_response()
    }
}

/// The response for a request that the shutdown drain deadline cancelled: the same 503
/// `dependency-failure` Problem an unavailable dependency gets. A retry with the same idempotency
/// key returns the prior result if the cancelled request had committed.
pub(crate) fn cancelled_at_shutdown() -> Response {
    ApiError::Service(ServiceError::Application(ApplicationError::Unavailable)).into_response()
}

fn service_problem(error: &ServiceError) -> (StatusCode, &'static str) {
    let status = match error {
        ServiceError::Application(ApplicationError::Unauthenticated) => StatusCode::UNAUTHORIZED,
        ServiceError::Application(ApplicationError::Forbidden) => StatusCode::FORBIDDEN,
        ServiceError::Application(ApplicationError::Replay) => StatusCode::CONFLICT,
        ServiceError::Application(
            ApplicationError::InvalidRequest
            | ApplicationError::InvalidDocument
            | ApplicationError::UnsupportedSchema
            | ApplicationError::KeyBinding
            | ApplicationError::PendingLimit
            | ApplicationError::InvalidEnvelope,
        ) => StatusCode::UNPROCESSABLE_ENTITY,
        ServiceError::Application(ApplicationError::IntegrityFailure) => StatusCode::CONFLICT,
        ServiceError::Application(ApplicationError::AuditIncomplete) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ServiceError::Application(ApplicationError::Unavailable | ApplicationError::Invariant)
        | ServiceError::Initialization(_) => StatusCode::SERVICE_UNAVAILABLE,
        #[cfg(feature = "test-support")]
        ServiceError::Inspection => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, error.category())
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::DemoHarness;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const PLAINTEXT: &[u8] = b"Please provide";

    struct Reply {
        status: u16,
        body: Vec<u8>,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).expect("JSON body")
        }

        fn reveals_plaintext(&self) -> bool {
            self.body
                .windows(PLAINTEXT.len())
                .any(|window| window == PLAINTEXT)
        }
    }

    /// Sends one raw HTTP/1.1 request to the router on an ephemeral loopback listener.
    async fn send(router: Router, request: &[u8]) -> Reply {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream.write_all(request).await.expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        server.abort();
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("header terminator");
        let status = std::str::from_utf8(&response[9..12])
            .expect("status digits")
            .parse()
            .expect("status code");
        Reply {
            status,
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

    fn send_copy_body() -> String {
        send_copy_body_for(1, 0xf0, "idem_0000000000000001")
    }

    fn send_copy_body_for(version: u64, nonce: u8, idempotency_key: &str) -> String {
        let document: Value = serde_json::from_slice(include_bytes!(
            "../../../schemas/service-application/example.json"
        ))
        .expect("example document");
        serde_json::json!({
            "sender": "wal_0000000000000001",
            "recipient": "wal_0000000000000002",
            "document_id": "doc_0000000000000001",
            "document_version": version,
            "request_nonce": URL_SAFE_NO_PAD.encode([nonce; 16]),
            "idempotency_key": idempotency_key,
            "schema_id": "urn:docchain:schema:service-application:1.0.0",
            "schema_version": "1.0.0",
            "document": document,
        })
        .to_string()
    }

    #[tokio::test]
    async fn router_rejects_forged_identity_oversize_overload_timeout_and_safe_errors() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        let inbox = "/v1/inboxes/wal_0000000000000001";

        let forged = send(app(), &get(inbox, &bearer("forged"))).await;
        assert_eq!(forged.status, 401);
        let missing = send(app(), &get(inbox, "")).await;
        assert_eq!(missing.status, 401);
        // A claimed wallet or role header is not an identity.
        let claimed = send(
            app(),
            &get(
                inbox,
                "x-docchain-wallet: wal_0000000000000001\r\nx-docchain-role: auditor\r\n",
            ),
        )
        .await;
        assert_eq!(claimed.status, 401);
        let claimed_audit = send(
            app(),
            &get("/v1/audit/verify", "x-docchain-role: auditor\r\n"),
        )
        .await;
        assert_eq!(claimed_audit.status, 401);
        // A verified wallet is still only itself.
        let other_inbox = send(app(), &get(inbox, &bearer(&harness.recipient_credential))).await;
        assert_eq!(other_inbox.status, 403);

        let oversized = send(
            app(),
            &post(
                "/v1/send-copies",
                &bearer(&harness.sender_credential),
                &"x".repeat(MAX_DOCUMENT_BYTES + 1),
            ),
        )
        .await;
        assert_eq!(oversized.status, 413);

        let overloaded = send(
            router(
                harness.service(),
                HttpConfig {
                    max_in_flight: 0,
                    ..HttpConfig::default()
                },
            ),
            &get(inbox, &bearer(&harness.sender_credential)),
        )
        .await;
        assert_eq!(overloaded.status, 503);
        let timed_out = send(
            router(
                harness.service(),
                HttpConfig {
                    request_timeout: Duration::from_millis(1),
                    max_in_flight: 1,
                },
            ),
            &get(inbox, "x-docchain-test-delay: yes\r\n"),
        )
        .await;
        assert_eq!(timed_out.status, 504);

        let invalid = send(
            app(),
            &post(
                "/v1/send-copies",
                &bearer(&harness.sender_credential),
                "Please provide private material",
            ),
        )
        .await;
        assert_eq!(invalid.status, 422);
        assert!(!invalid.reveals_plaintext());
    }

    #[tokio::test]
    async fn router_serves_the_exchange_to_its_participants_only() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());

        let delivered = send(
            app(),
            &post(
                "/v1/send-copies",
                &bearer(&harness.sender_credential),
                &send_copy_body(),
            ),
        )
        .await;
        assert_eq!(delivered.status, 201);
        let exchange = delivered.json()["exchange_id"]
            .as_str()
            .expect("exchange id")
            .to_owned();
        let replayed = send(
            app(),
            &post(
                "/v1/send-copies",
                &bearer(&harness.sender_credential),
                &send_copy_body(),
            ),
        )
        .await;
        assert_eq!((replayed.status, replayed.json()), (201, delivered.json()));
        // Another wallet cannot send as the sender, even with the sender's idempotency key.
        let impersonated = send(
            app(),
            &post(
                "/v1/send-copies",
                &bearer(&harness.unrelated_credential),
                &send_copy_body(),
            ),
        )
        .await;
        assert_eq!(impersonated.status, 403);

        let inbox = send(
            app(),
            &get(
                "/v1/inboxes/wal_0000000000000002",
                &bearer(&harness.recipient_credential),
            ),
        )
        .await;
        assert_eq!(inbox.status, 200);
        assert_eq!(inbox.json()["exchange_ids"], serde_json::json!([exchange]));

        let document = format!("/v1/exchanges/{exchange}/document");
        let unknown = "/v1/exchanges/exc_00000000000000000000000000000000/document";
        for credential in [
            &harness.unrelated_credential,
            &harness.operator_credential,
            &harness.auditor_credential,
        ] {
            for path in [document.as_str(), unknown] {
                let denied = send(app(), &get(path, &bearer(credential))).await;
                assert_eq!(denied.status, 403, "{path}");
                assert_eq!(denied.json(), serde_json::json!({"category": "forbidden"}));
                assert!(!denied.reveals_plaintext());
            }
        }
        let read = send(
            app(),
            &get(&document, &bearer(&harness.recipient_credential)),
        )
        .await;
        assert_eq!(read.status, 200);
        assert!(read.reveals_plaintext());

        let wallet_audit = send(
            app(),
            &get("/v1/audit/verify", &bearer(&harness.sender_credential)),
        )
        .await;
        assert_eq!(wallet_audit.status, 403);
        let audit = send(
            app(),
            &get("/v1/audit/verify", &bearer(&harness.auditor_credential)),
        )
        .await;
        assert_eq!(audit.status, 200);
        assert!(!audit.reveals_plaintext());
        let head = audit.json()["head"].clone();
        assert_eq!(
            (
                audit.json()["event_count"].clone(),
                head["sequence"].clone()
            ),
            (1.into(), 1.into())
        );
        let held = format!(
            "/v1/audit/verify?head_sequence=1&head_event_hash={}&head_signature={}",
            head["event_hash"].as_str().expect("hash"),
            head["signature"].as_str().expect("signature")
        );
        let still_there = send(app(), &get(&held, &bearer(&harness.auditor_credential))).await;
        assert_eq!(still_there.status, 200);
        // The table owner can bypass the append-only refusal; the held head still exposes it.
        harness
            .tamper_as_owner("DELETE FROM audit_events")
            .await
            .expect("remove events");
        let truncated = send(app(), &get(&held, &bearer(&harness.auditor_credential))).await;
        assert_eq!(truncated.status, 409);
        assert_eq!(
            truncated.json(),
            serde_json::json!({"category": "integrity-failure"})
        );
        let malformed = send(
            app(),
            &get(
                "/v1/audit/verify?head_sequence=1",
                &bearer(&harness.auditor_credential),
            ),
        )
        .await;
        assert_eq!(malformed.status, 422);
    }

    #[tokio::test]
    async fn acceptance_response_is_this_exchange_only() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        for (version, nonce, send_key, accept_key) in [
            (1, 0xf0, "idem_0000000000000001", "idem_accept0000000001"),
            (2, 0xf1, "idem_0000000000000002", "idem_accept0000000002"),
        ] {
            let delivered = send(
                app(),
                &post(
                    "/v1/send-copies",
                    &bearer(&harness.sender_credential),
                    &send_copy_body_for(version, nonce, send_key),
                ),
            )
            .await;
            assert_eq!(delivered.status, 201);
            let exchange = delivered.json()["exchange_id"].clone();
            let accepted = send(
                app(),
                &post(
                    &format!(
                        "/v1/exchanges/{}/acceptances",
                        exchange.as_str().expect("exchange id")
                    ),
                    &bearer(&harness.recipient_credential),
                    &serde_json::json!({"idempotency_key": accept_key}).to_string(),
                ),
            )
            .await;
            assert_eq!(accepted.status, 200);
            // The sender's second acceptance still reports this exchange and its one credit,
            // never a running balance.
            assert_eq!(
                accepted.json(),
                serde_json::json!({"exchange_id": exchange, "credit_awarded": 1})
            );
        }
    }

    #[tokio::test]
    async fn ready_is_503_when_the_document_root_is_gone() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        assert_eq!(send(app(), &get("/health/ready", "")).await.status, 204);
        harness
            .remove_document_root()
            .await
            .expect("remove document root");
        // A probe result answers readiness for one second; the next check probes afresh.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(send(app(), &get("/health/ready", "")).await.status, 503);
        assert_eq!(send(app(), &get("/health/live", "")).await.status, 204);
    }

    #[tokio::test]
    async fn audit_beyond_the_event_limit_is_503_audit_incomplete() {
        let harness = DemoHarness::new_with_limits(docchain_application::Limits {
            audit_events: 1,
            ..docchain_application::Limits::default()
        })
        .await
        .expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        for (version, nonce, key) in [
            (1, 0xf0, "idem_0000000000000001"),
            (2, 0xf1, "idem_0000000000000002"),
        ] {
            let delivered = send(
                app(),
                &post(
                    "/v1/send-copies",
                    &bearer(&harness.sender_credential),
                    &send_copy_body_for(version, nonce, key),
                ),
            )
            .await;
            assert_eq!(delivered.status, 201);
        }
        let audit = send(
            app(),
            &get("/v1/audit/verify", &bearer(&harness.auditor_credential)),
        )
        .await;
        assert_eq!(audit.status, 503);
        assert_eq!(
            audit.json(),
            serde_json::json!({"category": "audit-incomplete"})
        );
    }
}
