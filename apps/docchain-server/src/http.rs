//! Versioned HTTP adapter for the first private exchange.

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::rejection::BytesRejection,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode, Uri,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use docchain_application::{
    Actor, ApplicationError, AuditExportPage, AuditExportRequest, Coverage, Credential,
    SendCopyCommand,
};
use docchain_domain::{
    AuditChallenge, AuditExportManifest, AuditSnapshot, Checkpoint, DocumentId, DocumentVersion,
    ExchangeId, IdempotencyKey, MAX_DOCUMENT_BYTES, RequestNonce, WalletId, canonicalize,
    parse_bounded_json, parse_document,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{sync::Semaphore, time};

use crate::{
    DocchainService, ServiceError,
    diagnostics::{self, CountersSnapshot, Diagnostics, Outcome, UseCaseScope},
};

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
    diagnostics: Diagnostics,
}

#[derive(Clone)]
struct Gate {
    deadline: Duration,
    permits: Arc<Semaphore>,
}

/// Builds the version 1 API around the fully composed service, with diagnostics that write no
/// record. Counters still count.
///
/// Admission and the end-to-end deadline run before body extraction. Every business handler
/// authenticates a credential through the identity port before invoking a use case.
pub fn router(service: Arc<DocchainService>, config: HttpConfig) -> Router {
    router_with_diagnostics(service, config, Diagnostics::discarding())
}

/// Builds the version 1 API and the operational routes around the fully composed service, with
/// `diagnostics` recording one request span per request and one use-case span per application
/// call, and serving its counters to the operator.
///
/// Admission and the end-to-end deadline run before body extraction. Every business handler
/// authenticates a credential through the identity port before invoking a use case.
pub fn router_with_diagnostics(
    service: Arc<DocchainService>,
    config: HttpConfig,
    diagnostics: Diagnostics,
) -> Router {
    let state = HttpState {
        service,
        diagnostics: diagnostics.clone(),
    };
    let gate = Gate {
        deadline: config.request_timeout,
        permits: Arc::new(Semaphore::new(config.max_in_flight)),
    };
    let business = Router::new()
        .route(SEND_COPIES_ROUTE, post(send_copy))
        .route(ACCEPT_ROUTE, post(accept))
        .route(READ_DOCUMENT_ROUTE, get(read_document))
        .route(INBOX_ROUTE, get(list_inbox))
        .route(AUDIT_VERIFY_ROUTE, get(verify_audit))
        .route(
            AUDIT_KEY_ROUTE,
            get(audit_key).layer(DefaultBodyLimit::max(0)),
        )
        .route(
            AUDIT_EXPORT_ROUTE,
            post(export_audit_events).layer(DefaultBodyLimit::max(MAX_AUDIT_EXPORT_BODY)),
        )
        .route(
            COUNTERS_ROUTE,
            get(read_counters).layer(DefaultBodyLimit::max(0)),
        )
        .layer(DefaultBodyLimit::max(MAX_DOCUMENT_BYTES))
        .layer(middleware::from_fn_with_state(gate, admission));
    Router::new()
        .route(LIVE_ROUTE, get(live))
        .route(READY_ROUTE, get(ready))
        .merge(business)
        // The same empty 404 as the default, made explicit so the request span also wraps it.
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn(no_store))
        .layer(middleware::from_fn_with_state(
            diagnostics,
            diagnostics::request_span,
        ))
        .with_state(state)
}

pub(crate) const SEND_COPIES_ROUTE: &str = "/v1/send-copies";
pub(crate) const ACCEPT_ROUTE: &str = "/v1/exchanges/{exchange_id}/acceptances";
pub(crate) const READ_DOCUMENT_ROUTE: &str = "/v1/exchanges/{exchange_id}/document";
pub(crate) const INBOX_ROUTE: &str = "/v1/inboxes/{wallet_id}";
pub(crate) const AUDIT_VERIFY_ROUTE: &str = "/v1/audit/verify";
pub(crate) const AUDIT_KEY_ROUTE: &str = "/v1/audit/key";
pub(crate) const AUDIT_EXPORT_ROUTE: &str = "/v1/audit/events/export";
pub(crate) const LIVE_ROUTE: &str = "/health/live";
pub(crate) const READY_ROUTE: &str = "/health/ready";
/// Operational, outside `/v1`: the operator's view of the outcome counters.
pub(crate) const COUNTERS_ROUTE: &str = "/operations/counters";
/// Largest accepted export request body, in bytes.
const MAX_AUDIT_EXPORT_BODY: usize = 4 * 1024;
/// Deepest accepted export request nesting.
const MAX_AUDIT_EXPORT_DEPTH: usize = 4;

/// Marks every response on the audit proof routes and the counters route, including overload,
/// timeout, and method errors produced outside their handlers, as uncacheable. The routes have no
/// path parameters, so the path equals the route template. Serving applies it again outside its
/// shutdown cancellation, so a proof request cancelled at the drain deadline is marked too.
pub(crate) async fn no_store(request: Request, next: Next) -> Response {
    let proof_route = matches!(
        request.uri().path(),
        AUDIT_KEY_ROUTE | AUDIT_EXPORT_ROUTE | COUNTERS_ROUTE
    );
    let mut response = next.run(request).await;
    if proof_route {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
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

async fn ready(State(state): State<HttpState>, scope: UseCaseScope) -> Response {
    match scope.run(state.service.ready()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => {
            let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
            response.extensions_mut().insert(Outcome::NotReady);
            response
        }
    }
}

/// `GET /operations/counters`: the operation × outcome counters, for the operator only.
///
/// It works in the audit key handler's order: authenticate, then refuse a query or a body, then
/// authorize through the application, whose grant is the only way to read the counters.
async fn read_counters(
    State(state): State<HttpState>,
    scope: UseCaseScope,
    headers: HeaderMap,
    uri: Uri,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<CountersSnapshot>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    if uri.query().is_some() || !body.is_ok_and(|body| body.is_empty()) {
        return Err(ApiError::InvalidRequest);
    }
    let grant = scope.run_sync(|| state.service.authorize_operational_read(&actor))?;
    Ok(Json(state.diagnostics.counters().snapshot(&grant)))
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
    scope: UseCaseScope,
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
    let delivered = scope.run(state.service.send_copy(&actor, command)).await?;
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
    scope: UseCaseScope,
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
    let accepted = scope
        .run(state.service.accept(&actor, &exchange_id, &key))
        .await?;
    Ok(Json(AcceptanceDtoOut {
        exchange_id: accepted.exchange_id.to_string(),
        credit_awarded: accepted.credit_awarded,
    }))
}

async fn read_document(
    State(state): State<HttpState>,
    scope: UseCaseScope,
    Path(exchange_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let exchange_id = ExchangeId::new(exchange_id).map_err(|_| ApiError::InvalidRequest)?;
    let document = scope
        .run(state.service.read_document(&actor, &exchange_id))
        .await?;
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
    scope: UseCaseScope,
    Path(wallet_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<InboxDto>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let wallet = WalletId::new(wallet_id).map_err(|_| ApiError::InvalidRequest)?;
    let exchange_ids = scope
        .run(state.service.list_inbox(&actor, &wallet))
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
    credits: CreditReconciliationDto,
}

/// Every accepted exchange has exactly one balanced credit transaction, and every credit
/// transaction belongs to exactly one accepted exchange. Counts only; no identifier.
#[derive(Serialize)]
struct CreditReconciliationDto {
    reconciled: bool,
    accepted_exchanges: usize,
    credit_transactions: usize,
}

/// A signed chain head. An auditor keeps the one it last verified and presents it again, so
/// removing events after it is detected.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointDto {
    sequence: u64,
    event_hash: String,
    signature: String,
}

#[derive(Serialize)]
struct AuditKeyDto {
    public_key: String,
    fingerprint: String,
}

/// `GET /v1/audit/key`: the pinned audit public key and its fingerprint, for auditors only.
///
/// The request has no query and no body. The fingerprint in the response is never a trust
/// anchor: a verifier compares it with the value provisioned to it separately.
async fn audit_key(
    State(state): State<HttpState>,
    scope: UseCaseScope,
    headers: HeaderMap,
    uri: Uri,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<AuditKeyDto>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    if uri.query().is_some() || !body.is_ok_and(|body| body.is_empty()) {
        return Err(ApiError::InvalidRequest);
    }
    let proof = scope.run_sync(|| state.service.audit_public_key(&actor))?;
    Ok(Json(AuditKeyDto {
        public_key: URL_SAFE_NO_PAD.encode(proof.public_key()),
        fingerprint: URL_SAFE_NO_PAD.encode(proof.fingerprint().as_bytes()),
    }))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExportManifestDto {
    export_version: u8,
    challenge: String,
    audit_key_fingerprint: String,
    event_count: u64,
    head: Option<CheckpointDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportStartDto {
    challenge: String,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportContinueDto {
    manifest: ExportManifestDto,
    manifest_signature: String,
    after_sequence: u64,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ExportRequestDto {
    Start(ExportStartDto),
    Continue(ExportContinueDto),
}

#[derive(Serialize)]
struct ExportEventDto {
    preimage_version: u8,
    preimage: String,
    sequence: u64,
    previous_event_hash: String,
    event_hash: String,
    signature: String,
}

#[derive(Serialize)]
struct ExportPageDto {
    manifest: ExportManifestDto,
    manifest_signature: String,
    coverage: &'static str,
    events: Vec<ExportEventDto>,
    next_after_sequence: Option<u64>,
}

/// `POST /v1/audit/events/export`: one page of challenge-bound signed-event proof.
///
/// All proof travels in the closed JSON body, never the request target. A start body holds the
/// verifier's fresh `challenge`; a continuation repeats the signed `manifest` and its signature
/// with `after_sequence`. Both may add `limit`, from 1 through 500. Only the page ending at the
/// manifest's event count says `complete`. The first complete export is a baseline; a later
/// export detects rollback only at or before the newest checkpoint the auditor retained, and
/// neither proves absolute freshness.
async fn export_audit_events(
    State(state): State<HttpState>,
    scope: UseCaseScope,
    headers: HeaderMap,
    uri: Uri,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ExportPageDto>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    if uri.query().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let body = body.map_err(|_| ApiError::InvalidRequest)?;
    let strict = parse_bounded_json(&body, MAX_AUDIT_EXPORT_BODY, MAX_AUDIT_EXPORT_DEPTH)
        .map_err(|_| ApiError::InvalidRequest)?;
    // `limit` is optional, but when present it is an integer, never `null`.
    if strict.value().get("limit").is_some_and(Value::is_null) {
        return Err(ApiError::InvalidRequest);
    }
    let dto: ExportRequestDto =
        serde_json::from_value(strict.value().clone()).map_err(|_| ApiError::InvalidRequest)?;
    let request = match dto {
        ExportRequestDto::Start(start) => AuditExportRequest::start(
            AuditChallenge::new(strict_fixed(&start.challenge)?),
            start.limit,
        ),
        ExportRequestDto::Continue(continuation) => AuditExportRequest::continuation(
            manifest_from_dto(continuation.manifest)?,
            strict_fixed(&continuation.manifest_signature)?,
            continuation.after_sequence,
            continuation.limit,
        ),
    }
    .map_err(|_| ApiError::InvalidRequest)?;
    scope
        .run(state.service.export_audit_events(&actor, request))
        .await
        .map(export_page_dto)
        .map(Json)
        .map_err(Into::into)
}

fn manifest_from_dto(dto: ExportManifestDto) -> Result<AuditExportManifest, ApiError> {
    if dto.export_version != 1 {
        return Err(ApiError::InvalidRequest);
    }
    let head = dto
        .head
        .map(|head| -> Result<Checkpoint, ApiError> {
            Ok(Checkpoint {
                sequence: head.sequence,
                event_hash: strict_fixed(&head.event_hash)?,
                signature: strict_fixed(&head.signature)?,
            })
        })
        .transpose()?;
    let snapshot =
        AuditSnapshot::new(dto.event_count, head).map_err(|_| ApiError::InvalidRequest)?;
    Ok(AuditExportManifest::new(
        AuditChallenge::new(strict_fixed(&dto.challenge)?),
        strict_fixed(&dto.audit_key_fingerprint)?,
        snapshot,
    ))
}

fn manifest_dto(manifest: AuditExportManifest) -> ExportManifestDto {
    ExportManifestDto {
        export_version: 1,
        challenge: URL_SAFE_NO_PAD.encode(manifest.challenge().as_bytes()),
        audit_key_fingerprint: URL_SAFE_NO_PAD.encode(manifest.audit_key_fingerprint()),
        event_count: manifest.snapshot().event_count(),
        head: manifest.snapshot().head().map(|head| CheckpointDto {
            sequence: head.sequence,
            event_hash: URL_SAFE_NO_PAD.encode(head.event_hash),
            signature: URL_SAFE_NO_PAD.encode(head.signature),
        }),
    }
}

fn export_page_dto(page: AuditExportPage) -> ExportPageDto {
    ExportPageDto {
        manifest: manifest_dto(page.manifest),
        manifest_signature: URL_SAFE_NO_PAD.encode(page.manifest_signature),
        coverage: match page.coverage {
            Coverage::Partial => "partial",
            Coverage::Complete => "complete",
        },
        events: page
            .events
            .into_iter()
            .map(|event| ExportEventDto {
                preimage_version: event.preimage_version,
                preimage: URL_SAFE_NO_PAD.encode(event.preimage),
                sequence: event.sequence,
                previous_event_hash: URL_SAFE_NO_PAD.encode(event.previous_event_hash),
                event_hash: URL_SAFE_NO_PAD.encode(event.event_hash),
                signature: URL_SAFE_NO_PAD.encode(event.signature),
            })
            .collect(),
        next_after_sequence: page.next_after_sequence,
    }
}

async fn verify_audit(
    State(state): State<HttpState>,
    scope: UseCaseScope,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<AuditDto>, ApiError> {
    let actor = authenticate(&state, &headers).await?;
    let expected = expected_head(uri.query())?;
    let report = scope
        .run(state.service.verify_audit(&actor, expected))
        .await?;
    Ok(Json(AuditDto {
        valid: true,
        event_count: report.event_count,
        head: report.head.map(|head| CheckpointDto {
            sequence: head.sequence,
            event_hash: URL_SAFE_NO_PAD.encode(head.event_hash),
            signature: URL_SAFE_NO_PAD.encode(head.signature),
        }),
        credits: CreditReconciliationDto {
            reconciled: true,
            accepted_exchanges: report.credits.accepted_exchanges(),
            credit_transactions: report.credits.credit_transactions(),
        },
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

fn strict_fixed<const N: usize>(value: &str) -> Result<[u8; N], ApiError> {
    strict_b64(value)?
        .try_into()
        .map_err(|_| ApiError::InvalidRequest)
}

#[derive(Debug)]
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
    /// Only an audit verification failure carries a reason: the class of check that failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl ApiError {
    /// The diagnostic outcome, which matches the Problem category.
    const fn outcome(&self) -> Outcome {
        match self {
            Self::Unauthenticated => Outcome::Unauthenticated,
            Self::InvalidRequest => Outcome::InvalidRequest,
            Self::Overloaded => Outcome::Overloaded,
            Self::Timeout => Outcome::Timeout,
            Self::Service(error) => Outcome::from_service_error(error),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let outcome = self.outcome();
        let (status, category) = match &self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::InvalidRequest => (StatusCode::UNPROCESSABLE_ENTITY, "invalid-request"),
            Self::Overloaded => (StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Self::Service(error) => service_problem(error),
        };
        let reason = match self {
            Self::Service(ServiceError::Application(ApplicationError::AuditMismatch(mismatch))) => {
                Some(mismatch.as_str())
            }
            _ => None,
        };
        let mut response = (status, Json(Problem { category, reason })).into_response();
        response.extensions_mut().insert(outcome);
        response
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
        ServiceError::Application(
            ApplicationError::IntegrityFailure | ApplicationError::AuditMismatch(_),
        ) => StatusCode::CONFLICT,
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

#[cfg(test)]
mod outcome_tests {
    use docchain_application::AuditMismatch;

    use super::*;

    #[test]
    fn every_api_error_carries_the_outcome_named_by_its_category() {
        let mut errors = vec![
            ApiError::Unauthenticated,
            ApiError::InvalidRequest,
            ApiError::Overloaded,
            ApiError::Timeout,
            ApiError::Service(ServiceError::Initialization("database connection")),
        ];
        errors.extend(
            [
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
            .map(|error| ApiError::Service(ServiceError::Application(error))),
        );
        for error in errors {
            let expected = error.outcome();
            let response = error.into_response();
            assert_eq!(response.extensions().get::<Outcome>(), Some(&expected));
            assert_eq!(problem_body(response)["category"], expected.as_str());
        }
        // The shutdown cancellation is a dependency failure too.
        assert_eq!(
            cancelled_at_shutdown().extensions().get::<Outcome>(),
            Some(&Outcome::DependencyFailure)
        );
    }

    /// The Problem body of a response built in memory.
    fn problem_body(response: Response) -> Value {
        let bytes = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(axum::body::to_bytes(response.into_body(), 1_024))
            .expect("body");
        serde_json::from_slice(&bytes).expect("Problem JSON")
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::DemoHarness;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const PLAINTEXT: &[u8] = b"Please provide";

    struct Reply {
        status: u16,
        headers: Vec<u8>,
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

        fn no_store(&self) -> bool {
            String::from_utf8_lossy(&self.headers)
                .to_ascii_lowercase()
                .contains("cache-control: no-store")
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
            headers: response[..split].to_vec(),
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

    fn keys(value: &Value) -> Vec<&str> {
        value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    fn category(reply: &Reply) -> String {
        reply.json()["category"]
            .as_str()
            .expect("problem category")
            .to_owned()
    }

    /// Posts `body` to the export route as the auditor.
    async fn export(harness: &DemoHarness, body: &str) -> Reply {
        send(
            router(harness.service(), HttpConfig::default()),
            &post(
                "/v1/audit/events/export",
                &bearer(&harness.auditor_credential),
                body,
            ),
        )
        .await
    }

    /// Delivers and accepts one copy through HTTP, leaving two events.
    async fn two_events(harness: &DemoHarness) {
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
            .expect("exchange")
            .to_owned();
        let accepted = send(
            app(),
            &post(
                &format!("/v1/exchanges/{exchange}/acceptances"),
                &bearer(&harness.recipient_credential),
                r#"{"idempotency_key":"idem_accept0000000001"}"#,
            ),
        )
        .await;
        assert_eq!(accepted.status, 200);
    }

    #[tokio::test]
    async fn audit_key_contract_is_closed_authorized_and_no_store() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        let published = send(
            app(),
            &get("/v1/audit/key", &bearer(&harness.auditor_credential)),
        )
        .await;
        assert_eq!(published.status, 200);
        assert!(published.no_store());
        let value = published.json();
        assert_eq!(keys(&value), ["fingerprint", "public_key"]);
        let public_key = strict_fixed::<32>(value["public_key"].as_str().expect("public key"))
            .expect("canonical public key");
        let fingerprint = strict_fixed::<32>(value["fingerprint"].as_str().expect("fingerprint"))
            .expect("canonical fingerprint");
        assert_eq!(fingerprint, harness.expected_audit_fingerprint());
        assert_eq!(docchain_domain::sha256(&public_key), fingerprint);

        let cases = [
            (get("/v1/audit/key", ""), 401, "unauthenticated"),
            (get("/v1/audit/key", &bearer("unknown")), 401, "unauthenticated"),
            (
                get("/v1/audit/key", &bearer(&harness.sender_credential)),
                403,
                "forbidden",
            ),
            (
                get("/v1/audit/key", &bearer(&harness.operator_credential)),
                403,
                "forbidden",
            ),
            (
                get(
                    "/v1/audit/key?fingerprint=proof",
                    &bearer(&harness.auditor_credential),
                ),
                422,
                "invalid-request",
            ),
            (
                format!(
                    "GET /v1/audit/key HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}",
                    bearer(&harness.auditor_credential)
                )
                .into_bytes(),
                422,
                "invalid-request",
            ),
        ];
        for (request, status, expected) in cases {
            let denied = send(app(), &request).await;
            assert_eq!(denied.status, status);
            assert_eq!(category(&denied), expected);
            assert!(denied.no_store());
            assert!(
                !String::from_utf8_lossy(&denied.body).contains(&value["public_key"].to_string())
            );
        }
        let wrong_method = send(
            app(),
            &post("/v1/audit/key", &bearer(&harness.auditor_credential), "{}"),
        )
        .await;
        assert_eq!(wrong_method.status, 405);
        assert!(wrong_method.no_store());
    }

    #[tokio::test]
    async fn audit_export_translates_only_approved_proof_fields() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        two_events(&harness).await;
        let challenge = URL_SAFE_NO_PAD.encode([7; 32]);
        let start = serde_json::json!({"challenge": challenge}).to_string();
        let exported = export(&harness, &start).await;
        assert_eq!(exported.status, 200);
        assert!(exported.no_store());
        let value = exported.json();
        assert_eq!(
            keys(&value),
            [
                "coverage",
                "events",
                "manifest",
                "manifest_signature",
                "next_after_sequence"
            ]
        );
        assert_eq!(
            keys(&value["manifest"]),
            [
                "audit_key_fingerprint",
                "challenge",
                "event_count",
                "export_version",
                "head"
            ]
        );
        assert_eq!(value["manifest"]["export_version"], 1);
        assert_eq!(value["manifest"]["challenge"], challenge.as_str());
        assert_eq!(
            keys(&value["manifest"]["head"]),
            ["event_hash", "sequence", "signature"]
        );
        let events = value["events"].as_array().expect("events");
        assert_eq!(events.len(), 2);
        for event in events {
            assert_eq!(
                keys(event),
                [
                    "event_hash",
                    "preimage",
                    "preimage_version",
                    "previous_event_hash",
                    "sequence",
                    "signature"
                ]
            );
            assert_eq!(event["preimage_version"], 1);
            let preimage = strict_b64(event["preimage"].as_str().expect("preimage"))
                .expect("canonical preimage");
            assert_eq!(
                URL_SAFE_NO_PAD.encode(docchain_domain::sha256(&preimage)),
                event["event_hash"].as_str().expect("hash")
            );
        }
        assert_eq!(value["coverage"], "complete");
        assert_eq!(value["next_after_sequence"], Value::Null);
        assert!(!exported.reveals_plaintext());
        let text = String::from_utf8(exported.body.clone()).expect("JSON");
        for prohibited in [
            harness.auditor_credential.as_str(),
            harness.sender_credential.as_str(),
            "plaintext",
            "private",
            "envelope",
        ] {
            assert!(!text.contains(prohibited), "{prohibited}");
        }

        let mut rejected = vec![
            (
                send(app(), &post("/v1/audit/events/export", "", &start)).await,
                401,
            ),
            (
                send(
                    app(),
                    &post(
                        "/v1/audit/events/export",
                        &bearer(&harness.recipient_credential),
                        &start,
                    ),
                )
                .await,
                403,
            ),
            (
                send(
                    app(),
                    &post(
                        "/v1/audit/events/export",
                        &bearer(&harness.operator_credential),
                        &start,
                    ),
                )
                .await,
                403,
            ),
            (
                send(
                    app(),
                    &post(
                        &format!("/v1/audit/events/export?challenge={challenge}"),
                        &bearer(&harness.auditor_credential),
                        &start,
                    ),
                )
                .await,
                422,
            ),
        ];
        let long = URL_SAFE_NO_PAD.encode([7; 33]);
        let padded = format!("{challenge}=");
        let over_body = format!(
            r#"{{"challenge":"{challenge}","limit":1{}}}"#,
            " ".repeat(MAX_AUDIT_EXPORT_BODY)
        );
        for body in [
            format!(r#"{{"challenge":"{challenge}","unknown":true}}"#),
            format!(r#"{{"challenge":"{challenge}","challenge":"{challenge}"}}"#),
            format!(r#"{{"challenge":"{challenge}","after_sequence":1}}"#),
            format!(r#"{{"challenge":"{challenge}","limit":null}}"#),
            format!(r#"{{"challenge":"{challenge}","limit":0}}"#),
            format!(r#"{{"challenge":"{challenge}","limit":501}}"#),
            format!(r#"{{"challenge":"{long}"}}"#),
            format!(r#"{{"challenge":"{padded}"}}"#),
            r#"{"challenge":"AAAA+/AA"}"#.to_owned(),
            r#"{"challenge":[[[["deep"]]]]}"#.to_owned(),
            "{}".to_owned(),
            over_body,
        ] {
            rejected.push((export(&harness, &body).await, 422));
        }
        for (reply, status) in &rejected {
            assert_eq!(reply.status, *status);
            assert!(reply.no_store());
            assert_eq!(keys(&reply.json()), ["category"]);
        }
        let wrong_method = send(
            app(),
            &get(
                "/v1/audit/events/export",
                &bearer(&harness.auditor_credential),
            ),
        )
        .await;
        assert_eq!(wrong_method.status, 405);
        assert!(wrong_method.no_store());
        let overloaded = send(
            router(
                harness.service(),
                HttpConfig {
                    max_in_flight: 0,
                    ..HttpConfig::default()
                },
            ),
            &post(
                "/v1/audit/events/export",
                &bearer(&harness.auditor_credential),
                &start,
            ),
        )
        .await;
        assert_eq!(overloaded.status, 503);
        assert!(overloaded.no_store());
        let other_route = send(
            app(),
            &get("/v1/audit/verify", &bearer(&harness.auditor_credential)),
        )
        .await;
        assert!(!other_route.no_store());
    }

    #[tokio::test]
    async fn audit_export_reports_partial_until_manifest_complete() {
        let harness = DemoHarness::new().await.expect("harness");
        let empty = export(
            &harness,
            &serde_json::json!({"challenge": URL_SAFE_NO_PAD.encode([5; 32])}).to_string(),
        )
        .await
        .json();
        assert_eq!(
            (
                &empty["coverage"],
                &empty["manifest"]["event_count"],
                &empty["manifest"]["head"],
                &empty["next_after_sequence"]
            ),
            (
                &Value::from("complete"),
                &Value::from(0),
                &Value::Null,
                &Value::Null
            )
        );
        assert_eq!(empty["events"], serde_json::json!([]));

        two_events(&harness).await;
        let first = export(
            &harness,
            &serde_json::json!({"challenge": URL_SAFE_NO_PAD.encode([8; 32]), "limit": 1})
                .to_string(),
        )
        .await;
        assert_eq!(first.status, 200);
        let first = first.json();
        assert_eq!(first["coverage"], "partial");
        assert_eq!(first["next_after_sequence"], 1);
        assert_eq!(first["manifest"]["event_count"], 2);
        assert_eq!(first["manifest"]["head"]["sequence"], 2);
        let continuation = |manifest: &Value, signature: &Value, after: u64| {
            serde_json::json!({
                "manifest": manifest,
                "manifest_signature": signature,
                "after_sequence": after,
                "limit": 1
            })
            .to_string()
        };
        let second = export(
            &harness,
            &continuation(&first["manifest"], &first["manifest_signature"], 1),
        )
        .await;
        assert_eq!(second.status, 200);
        assert!(second.no_store());
        let second = second.json();
        assert_eq!(second["coverage"], "complete");
        assert_eq!(second["next_after_sequence"], Value::Null);
        assert_eq!(second["events"][0]["sequence"], 2);
        assert_eq!(second["manifest"], first["manifest"]);
        assert_eq!(second["manifest_signature"], first["manifest_signature"]);

        // A changed, re-challenged, or unsigned manifest and an out-of-snapshot cursor fail.
        let mut changed = first["manifest"].clone();
        changed["event_count"] = Value::from(1);
        changed["head"]["sequence"] = Value::from(1);
        let mut rechallenged = first["manifest"].clone();
        rechallenged["challenge"] = Value::from(URL_SAFE_NO_PAD.encode([9; 32]));
        let mut extra = first["manifest"].clone();
        extra["head"]["extra"] = Value::from(1);
        let mut version = first["manifest"].clone();
        version["export_version"] = Value::from(2);
        let mut bad_signature =
            strict_fixed::<64>(first["manifest_signature"].as_str().expect("signature"))
                .expect("signature bytes");
        bad_signature[0] ^= 1;
        let bad_signature = Value::from(URL_SAFE_NO_PAD.encode(bad_signature));
        let signature = &first["manifest_signature"];
        for body in [
            continuation(&changed, signature, 1),
            continuation(&rechallenged, signature, 1),
            continuation(&extra, signature, 1),
            continuation(&version, signature, 1),
            continuation(&first["manifest"], &bad_signature, 1),
            continuation(&first["manifest"], signature, 0),
            continuation(&first["manifest"], signature, 2),
        ] {
            let reply = export(&harness, &body).await;
            assert_eq!(
                (reply.status, category(&reply)),
                (422, "invalid-request".to_owned())
            );
            assert!(reply.no_store());
        }

        // Removing the signed head makes the continuation an integrity failure, not a prefix.
        harness.truncate_last_event().await.expect("truncate");
        let reply = export(&harness, &continuation(&first["manifest"], signature, 1)).await;
        assert_eq!(
            (reply.status, category(&reply)),
            (409, "integrity-failure".to_owned())
        );
        assert!(reply.no_store());
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
        // No exchange is accepted yet, so the reconciled ledger is empty.
        assert_eq!(
            audit.json()["credits"],
            serde_json::json!({"reconciled": true, "accepted_exchanges": 0, "credit_transactions": 0})
        );
        assert_eq!(
            keys(&audit.json()),
            ["credits", "event_count", "head", "valid"]
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
            serde_json::json!({"category": "integrity-failure", "reason": "event-chain"})
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
    async fn unmatched_paths_keep_the_empty_404_and_counters_are_no_store() {
        let harness = DemoHarness::new().await.expect("harness");
        let app = || router(harness.service(), HttpConfig::default());
        let missing = send(app(), &get("/v1/unknown", "")).await;
        assert_eq!(missing.status, 404);
        assert!(missing.body.is_empty());
        assert!(!missing.no_store());
        for credential in ["", &bearer(&harness.operator_credential)] {
            let reply = send(app(), &get(COUNTERS_ROUTE, credential)).await;
            assert!(reply.no_store(), "{}", reply.status);
        }
        let wrong_method = send(app(), &post(COUNTERS_ROUTE, "", "")).await;
        assert_eq!(wrong_method.status, 405);
        assert!(wrong_method.no_store());
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
