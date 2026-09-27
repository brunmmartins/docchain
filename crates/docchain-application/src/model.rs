use std::fmt;

use docchain_domain::{
    AuditChallenge, AuditEvent, AuditExportManifest, Checkpoint, CreditMismatch,
    CreditReconciliation, DocumentId, DocumentVersion, DomainError, ExchangeId, IdempotencyKey,
    ObjectId, RequestNonce, WalletId, sha256,
};
use thiserror::Error;

/// Who is calling, as established by the identity port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actor {
    /// A verified synthetic wallet.
    Wallet(WalletId),
    /// An authorized auditor: ciphertext and event integrity only, never plaintext.
    Auditor,
    /// An ordinary platform operator: no document access.
    Operator,
}

/// A credential presented by a client. `Debug` is redacted.
#[derive(Clone)]
pub struct Credential(String);

impl Credential {
    /// Wraps a presented credential.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// The presented value.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential(redacted)")
    }
}

/// Document plaintext released only to a verified participant.
///
/// `Debug` is redacted and the bytes are overwritten on drop. Overwriting is best effort:
/// earlier copies made by the allocator or libraries are outside this guarantee.
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    /// Takes ownership of plaintext bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The plaintext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Plaintext(redacted)")
    }
}

/// A request to send one encrypted copy of a document.
///
/// `Debug` is redacted because `document` is plaintext, and `document` is overwritten on drop,
/// as [`Plaintext`] is. Each clone clears its own buffer.
#[derive(Clone)]
pub struct SendCopyCommand {
    /// The sending wallet; it must be the authenticated actor.
    pub sender: WalletId,
    /// The receiving wallet.
    pub recipient: WalletId,
    /// The document.
    pub document_id: DocumentId,
    /// The document version.
    pub document_version: DocumentVersion,
    /// A nonce unique to this sender's request.
    pub request_nonce: RequestNonce,
    /// The sender-scoped idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// The exact schema `$id`.
    pub schema_id: String,
    /// The exact schema version.
    pub schema_version: String,
    /// The raw document JSON.
    pub document: Vec<u8>,
}

impl Drop for SendCopyCommand {
    fn drop(&mut self) {
        self.document.fill(0);
        std::hint::black_box(&self.document);
    }
}

impl fmt::Debug for SendCopyCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SendCopyCommand(redacted)")
    }
}

/// The committed result of a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The exchange.
    pub exchange_id: ExchangeId,
    /// The stored ciphertext envelope.
    pub object_id: ObjectId,
    /// SHA-256 of the exact stored envelope.
    pub envelope_commitment: [u8; 32],
}

/// The result of an acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceResult {
    /// The accepted exchange.
    pub exchange_id: ExchangeId,
    /// Credits awarded by this acceptance. This is always one.
    pub credit_awarded: i64,
}

/// The result of an audit verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    /// How many events verified.
    pub event_count: usize,
    /// The verified head, which the auditor keeps to detect later truncation.
    pub head: Option<Checkpoint>,
    /// The credit ledger reconciled with the verified acceptances.
    pub credits: CreditReconciliation,
}

/// A separately provisioned SHA-256 fingerprint of the expected audit public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditKeyPin([u8; 32]);

impl fmt::Debug for AuditKeyPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditKeyPin(redacted)")
    }
}

impl AuditKeyPin {
    /// Constructs a pin from exactly one digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// The public half of the audit key together with its independently configured pin.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditPublicKey {
    public_key: [u8; 32],
    fingerprint: AuditKeyPin,
}

impl fmt::Debug for AuditPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditPublicKey(redacted)")
    }
}

impl AuditPublicKey {
    /// Checks that the configured pin is SHA-256 of `public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::Invariant`] for a mismatched pin.
    pub fn new(public_key: [u8; 32], fingerprint: AuditKeyPin) -> Result<Self, ApplicationError> {
        if sha256(&public_key) != fingerprint.as_bytes() {
            return Err(ApplicationError::Invariant);
        }
        Ok(Self {
            public_key,
            fingerprint,
        })
    }

    /// The Ed25519 public key bytes.
    #[must_use]
    pub const fn public_key(self) -> [u8; 32] {
        self.public_key
    }

    /// The verified public-key fingerprint.
    #[must_use]
    pub const fn fingerprint(self) -> AuditKeyPin {
        self.fingerprint
    }
}

/// Validated audit proof and export bounds injected at composition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditSettings {
    public_key: AuditPublicKey,
    max_export_events: u32,
    default_page_size: u32,
}

impl fmt::Debug for AuditSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditSettings(redacted)")
    }
}

impl AuditSettings {
    /// Validates the fixed public bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::InvalidRequest`] unless the total is 1..=100,000 and the
    /// default page size is 1..=500.
    pub fn new(
        public_key: AuditPublicKey,
        max_export_events: u32,
        default_page_size: u32,
    ) -> Result<Self, ApplicationError> {
        if !(1..=100_000).contains(&max_export_events) || !(1..=500).contains(&default_page_size) {
            return Err(ApplicationError::InvalidRequest);
        }
        Ok(Self {
            public_key,
            max_export_events,
            default_page_size,
        })
    }

    /// The pinned public proof.
    #[must_use]
    pub const fn public_key(self) -> AuditPublicKey {
        self.public_key
    }

    /// Maximum complete snapshot size.
    #[must_use]
    pub const fn max_export_events(self) -> u32 {
        self.max_export_events
    }

    /// Page size used when a request omits it.
    #[must_use]
    pub const fn default_page_size(self) -> u32 {
        self.default_page_size
    }
}

/// A validated request for the first or a later page of one audit export.
///
/// Fields are private, so every request passes [`AuditExportRequest::start`] or
/// [`AuditExportRequest::continuation`] and carries a bounded page size and cursor.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditExportRequest {
    pub(crate) kind: AuditExportKind,
    limit: Option<u32>,
}

/// Which page of an export a validated request asks for.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AuditExportKind {
    /// Select a new snapshot for the verifier's challenge.
    Start { challenge: AuditChallenge },
    /// Continue the snapshot named by a signed manifest, after a sequence already received
    /// that lies inside that snapshot.
    Continue {
        manifest: Box<AuditExportManifest>,
        manifest_signature: [u8; 64],
        after_sequence: u64,
    },
}

impl fmt::Debug for AuditExportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditExportRequest(redacted)")
    }
}

impl AuditExportRequest {
    /// Constructs a bounded start request.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::InvalidRequest`] for a page size outside 1..=500.
    pub fn start(challenge: AuditChallenge, limit: Option<u32>) -> Result<Self, ApplicationError> {
        validate_page_size(limit)?;
        Ok(Self {
            kind: AuditExportKind::Start { challenge },
            limit,
        })
    }

    /// Constructs a bounded continuation request.
    ///
    /// # Errors
    ///
    /// Returns [`ApplicationError::InvalidRequest`] for a page size outside 1..=500, or a
    /// cursor that is zero or not before the manifest's last sequence.
    pub fn continuation(
        manifest: AuditExportManifest,
        manifest_signature: [u8; 64],
        after_sequence: u64,
        limit: Option<u32>,
    ) -> Result<Self, ApplicationError> {
        validate_page_size(limit)?;
        if after_sequence == 0 || after_sequence >= manifest.snapshot().event_count() {
            return Err(ApplicationError::InvalidRequest);
        }
        Ok(Self {
            kind: AuditExportKind::Continue {
                manifest: Box::new(manifest),
                manifest_signature,
                after_sequence,
            },
            limit,
        })
    }

    pub(crate) fn page_size(&self, default: u32) -> u32 {
        self.limit.unwrap_or(default)
    }
}

fn validate_page_size(limit: Option<u32>) -> Result<(), ApplicationError> {
    if limit.is_some_and(|limit| !(1..=500).contains(&limit)) {
        return Err(ApplicationError::InvalidRequest);
    }
    Ok(())
}

/// One exact signed event proof returned in an export page.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditExportEvent {
    /// Preimage format version.
    pub preimage_version: u8,
    /// Exact bytes whose SHA-256 digest is `event_hash`.
    pub preimage: Vec<u8>,
    /// Chain sequence.
    pub sequence: u64,
    /// Previous event hash.
    pub previous_event_hash: [u8; 32],
    /// Hash of `preimage`.
    pub event_hash: [u8; 32],
    /// Audit-key signature over the event signature input.
    pub signature: [u8; 64],
}

impl fmt::Debug for AuditExportEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditExportEvent(redacted)")
    }
}

impl AuditExportEvent {
    pub(crate) fn from_stored(event: AuditEvent) -> Result<Self, ApplicationError> {
        let preimage = event
            .preimage_v1()
            .map_err(|_| ApplicationError::IntegrityFailure)?;
        if sha256(&preimage) != event.event_hash {
            return Err(ApplicationError::IntegrityFailure);
        }
        Ok(Self {
            preimage_version: docchain_domain::AUDIT_PREIMAGE_VERSION,
            preimage,
            sequence: event.sequence,
            previous_event_hash: event.previous_hash,
            event_hash: event.event_hash,
            signature: event.signature,
        })
    }
}

/// Whether a page is only a prefix or completes its signed snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// More pages are required.
    Partial,
    /// This page completes the manifest snapshot.
    Complete,
}

/// One bounded page of challenge-bound independent audit evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditExportPage {
    /// Identical signed manifest repeated on every page.
    pub manifest: AuditExportManifest,
    /// Audit-key signature over the manifest.
    pub manifest_signature: [u8; 64],
    /// Whether all manifest events have now been returned.
    pub coverage: Coverage,
    /// Ordered exact event proofs.
    pub events: Vec<AuditExportEvent>,
    /// Last returned sequence for a continuation, or `None` when complete.
    pub next_after_sequence: Option<u64>,
}

impl fmt::Debug for AuditExportPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditExportPage(redacted)")
    }
}

/// Bounds the use cases enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most unaccepted exchanges one sender may have pending with one recipient.
    pub pending_per_relationship: u32,
    /// Most exchange identifiers one inbox listing returns.
    pub inbox_page: u32,
    /// Most events one audit verification reads.
    pub audit_events: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pending_per_relationship: 100,
            inbox_page: 100,
            audit_events: 100_000,
        }
    }
}

/// Stable failure categories of the use cases.
///
/// No variant carries document content, key material, or a dependency's error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ApplicationError {
    /// The credential is missing, unknown, or inactive.
    #[error("unauthenticated")]
    Unauthenticated,
    /// The actor may not perform this action on this resource, or the resource does not exist.
    #[error("request is not authorized")]
    Forbidden,
    /// The request is malformed.
    #[error("invalid request")]
    InvalidRequest,
    /// The document is not strict JSON or does not satisfy its schema.
    #[error("invalid document")]
    InvalidDocument,
    /// The schema is unknown, inactive, does not match its pinned digest, or is unsupported.
    #[error("unsupported schema")]
    UnsupportedSchema,
    /// A wallet has no active, valid key binding for the purpose.
    #[error("key binding unavailable")]
    KeyBinding,
    /// The request replays an earlier one with different content, or conflicts with it.
    #[error("replayed operation")]
    Replay,
    /// The sender already has the maximum pending exchanges with this recipient.
    #[error("pending limit reached")]
    PendingLimit,
    /// A stored envelope failed a check before plaintext could be released.
    #[error("invalid envelope")]
    InvalidEnvelope,
    /// The event chain or a ciphertext commitment failed verification.
    #[error("integrity failure")]
    IntegrityFailure,
    /// Audit verification failed, for the stated class of check only.
    #[error("integrity failure")]
    AuditMismatch(AuditMismatch),
    /// More events exist than the bounded audit can verify.
    #[error("audit incomplete")]
    AuditIncomplete,
    /// A dependency is unavailable or randomness failed; retrying may succeed.
    #[error("dependency unavailable")]
    Unavailable,
    /// Stored state broke an invariant.
    #[error("application invariant failed")]
    Invariant,
}

/// The class of check that failed audit verification. Checks run in the order chain,
/// envelopes, credits, and the first failure answers. No class carries an identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditMismatch {
    /// A hash, link, signature, count, page, held-checkpoint, or snapshot check failed, or an
    /// exchange was accepted twice.
    EventChain,
    /// A stored envelope is missing, or its commitment or header does not match its event.
    EnvelopeCommitment,
    /// A credit transaction or entry refers to no verified accepted exchange.
    CreditUnaccepted,
    /// An accepted exchange has more than one credit transaction.
    CreditDuplicate,
    /// An accepted exchange's credit transaction has the wrong key or entries.
    CreditUnbalanced,
    /// An accepted exchange has no credit transaction.
    CreditMissing,
}

impl AuditMismatch {
    /// The stable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventChain => "event-chain",
            Self::EnvelopeCommitment => "envelope-commitment",
            Self::CreditUnaccepted => "credit-unaccepted",
            Self::CreditDuplicate => "credit-duplicate",
            Self::CreditUnbalanced => "credit-unbalanced",
            Self::CreditMissing => "credit-missing",
        }
    }
}

impl From<CreditMismatch> for AuditMismatch {
    fn from(mismatch: CreditMismatch) -> Self {
        match mismatch {
            CreditMismatch::Unaccepted => Self::CreditUnaccepted,
            CreditMismatch::Duplicate => Self::CreditDuplicate,
            CreditMismatch::Unbalanced => Self::CreditUnbalanced,
            CreditMismatch::Missing => Self::CreditMissing,
        }
    }
}

impl From<DomainError> for ApplicationError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::Schema | DomainError::InvalidJson | DomainError::Bound(_) => {
                Self::InvalidDocument
            }
            DomainError::UnsupportedSchema => Self::UnsupportedSchema,
            DomainError::InvalidIdentifier { .. } => Self::InvalidRequest,
            DomainError::InvalidTimestamp | DomainError::EventIntegrity => Self::Invariant,
        }
    }
}
