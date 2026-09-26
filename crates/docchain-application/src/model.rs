use std::fmt;

use docchain_domain::{
    Checkpoint, DocumentId, DocumentVersion, DomainError, ExchangeId, IdempotencyKey, ObjectId,
    RequestNonce, WalletId,
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
