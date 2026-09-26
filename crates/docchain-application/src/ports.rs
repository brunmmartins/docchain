//! Outbound ports. Adapters implement them; use cases are generic over them.
//!
//! Async operations return `Send` futures and use static dispatch. Synchronous ports are
//! CPU-bound. Each port has its own error type, and none carries a dependency's error.

use std::future::Future;

use docchain_domain::{
    AuditEvent, DocumentId, DocumentVersion, EventDraft, ExchangeId, IdempotencyKey, ObjectId,
    RequestNonce, Timestamp, WalletId,
};
use thiserror::Error;

use crate::{Actor, Credential, Plaintext};

/// Identity port failures.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    /// The credential is unknown or malformed.
    #[error("unauthorized")]
    Unauthorized,
    /// The principal exists but is not active.
    #[error("inactive")]
    Inactive,
    /// The identity source is temporarily unavailable.
    #[error("transient")]
    Transient,
    /// The identity source failed permanently.
    #[error("permanent")]
    Permanent,
}

/// Verifies presented credentials.
pub trait Identity: Send + Sync {
    /// Resolves a credential to its actor.
    fn authenticate(
        &self,
        credential: &Credential,
    ) -> impl Future<Output = Result<Actor, IdentityError>> + Send;
}

/// Schema registry failures.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SchemaRegistryError {
    /// No schema has this identifier and version.
    #[error("not found")]
    NotFound,
    /// The schema exists but is not active.
    #[error("inactive")]
    Inactive,
    /// The registry is temporarily unavailable.
    #[error("transient")]
    Transient,
    /// The registry failed permanently.
    #[error("permanent")]
    Permanent,
}

/// An active schema artifact and the digest its authority approved.
#[derive(Clone, Debug)]
pub struct SchemaArtifact {
    /// The exact `$id`.
    pub id: String,
    /// The exact version.
    pub version: String,
    /// The artifact bytes as stored.
    pub bytes: Vec<u8>,
    /// SHA-256 over the artifact's RFC 8785 form, as approved.
    pub approved_digest: [u8; 32],
}

/// Supplies approved schema artifacts.
pub trait SchemaRegistry: Send + Sync {
    /// Loads the active artifact for an exact identifier and version.
    fn load_active(
        &self,
        schema_id: &str,
        version: &str,
    ) -> impl Future<Output = Result<SchemaArtifact, SchemaRegistryError>> + Send;
}

/// What a key is bound for. Signing and encryption keys never substitute for each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    /// Ed25519 document signing.
    DocumentSigning,
    /// X25519 document encryption.
    DocumentEncryption,
}

/// Key registry failures.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum KeyRegistryError {
    /// No binding matches.
    #[error("not found")]
    NotFound,
    /// A binding record failed authentication or its rules.
    #[error("invalid binding")]
    InvalidBinding,
    /// No binding is valid yet.
    #[error("inactive")]
    Inactive,
    /// The key is revoked.
    #[error("revoked")]
    Revoked,
    /// The binding's validity ended.
    #[error("expired")]
    Expired,
    /// The key is bound for another purpose.
    #[error("wrong purpose")]
    WrongPurpose,
    /// The registry is temporarily unavailable.
    #[error("transient")]
    Transient,
    /// The registry failed permanently.
    #[error("permanent")]
    Permanent,
}

/// A wallet-to-key binding whose authority signature and rules the registry verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBinding {
    /// The bound wallet.
    pub wallet: WalletId,
    /// The binding purpose.
    pub purpose: KeyPurpose,
    /// The purpose-prefixed key identifier derived from the public key.
    pub key_id: String,
    /// The exact 32-byte public key.
    pub public_key: [u8; 32],
    /// SHA-256 over the exact binding record.
    pub binding_digest: [u8; 32],
    /// The registry sequence of this binding record.
    pub sequence: u64,
}

/// Resolves authenticated wallet-to-key bindings.
pub trait KeyRegistry: Send + Sync {
    /// The newest binding for `wallet` and `purpose` that is active and valid at `at`.
    fn resolve_active(
        &self,
        wallet: &WalletId,
        purpose: KeyPurpose,
        at: Timestamp,
    ) -> impl Future<Output = Result<VerifiedBinding, KeyRegistryError>> + Send;

    /// A historic binding by the digest of its record.
    fn load(
        &self,
        binding_digest: &[u8; 32],
    ) -> impl Future<Output = Result<VerifiedBinding, KeyRegistryError>> + Send;

    /// The key's record in force at `at`, considering only records up to and including registry
    /// `sequence`, by the same rule [`KeyRegistry::resolve_active`] applies at the head.
    ///
    /// Among those records, the one with the highest sequence whose validity has started by `at`
    /// is in force. It counts only when it is active and `at` is before its end.
    ///
    /// # Errors
    ///
    /// [`KeyRegistryError::NotFound`] when the key has no record up to `sequence`;
    /// [`KeyRegistryError::Inactive`] when none of them is in force yet;
    /// [`KeyRegistryError::Revoked`] or [`KeyRegistryError::Expired`] for the record in force.
    fn effective_as_of(
        &self,
        key_id: &str,
        sequence: u64,
        at: Timestamp,
    ) -> impl Future<Output = Result<VerifiedBinding, KeyRegistryError>> + Send;

    /// The newest registry sequence, recorded with each commit.
    fn head_sequence(&self) -> impl Future<Output = Result<u64, KeyRegistryError>> + Send;
}

/// Envelope cryptography failures. They are deliberately coarse to avoid oracles.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// An input violates the envelope contract.
    #[error("invalid input")]
    InvalidInput,
    /// A key or binding is unusable, or no private key is held for it.
    #[error("invalid key or binding")]
    InvalidKey,
    /// The envelope names an unsupported suite or version.
    #[error("unsupported suite")]
    UnsupportedSuite,
    /// Authentication, decryption, or signature verification failed.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The CSPRNG failed; nothing was produced.
    #[error("entropy exhausted")]
    EntropyExhausted,
    /// Any other failure.
    #[error("permanent")]
    Permanent,
}

/// What a new envelope binds.
pub struct SealRequest<'a> {
    /// The RFC 8785 bytes of the schema-valid document.
    pub canonical_document: &'a [u8],
    /// The document.
    pub document_id: &'a DocumentId,
    /// The document version.
    pub document_version: DocumentVersion,
    /// The sender's request nonce.
    pub request_nonce: &'a RequestNonce,
    /// The exact schema `$id`.
    pub schema_id: &'a str,
    /// The recomputed schema digest.
    pub schema_digest: [u8; 32],
    /// The sender's active signing binding.
    pub sender_signing: &'a VerifiedBinding,
    /// Active encryption bindings for the sender and recipient wallets.
    pub recipients: [&'a VerifiedBinding; 2],
}

/// A sealed envelope ready to store.
#[derive(Clone, Debug)]
pub struct SealedEnvelope {
    /// The exact canonical envelope bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`.
    pub commitment: [u8; 32],
    /// SHA-256 of the protected header.
    pub protected_hash: [u8; 32],
    /// The envelope format version.
    pub envelope_version: u32,
}

/// One key descriptor in a protected header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderKey {
    /// The wallet.
    pub wallet: WalletId,
    /// The key identifier.
    pub key_id: String,
    /// The binding record digest the header pins.
    pub binding_digest: [u8; 32],
}

/// The validated protected header of a stored envelope. It holds no plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeHeader {
    /// The envelope format version.
    pub envelope_version: u32,
    /// SHA-256 of the protected header bytes.
    pub protected_hash: [u8; 32],
    /// The document.
    pub document_id: DocumentId,
    /// The document version.
    pub document_version: DocumentVersion,
    /// The exact schema `$id`.
    pub schema_id: String,
    /// The pinned schema digest.
    pub schema_digest: [u8; 32],
    /// The sender's signing key.
    pub sender: HeaderKey,
    /// The recipient encryption keys, in header order.
    pub recipients: Vec<HeaderKey>,
}

/// What opening an envelope needs beyond its bytes.
pub struct OpenRequest<'a> {
    /// The header previously returned by [`EnvelopeCryptography::inspect`] for these bytes.
    pub header: &'a EnvelopeHeader,
    /// The reader's verified encryption binding, which the header must name.
    pub reader: &'a VerifiedBinding,
    /// The sender's verified historic signing binding, which the header must pin.
    pub sender_signing: &'a VerifiedBinding,
}

/// Seals and opens version 1 envelopes.
pub trait EnvelopeCryptography: Send + Sync {
    /// Signs, encrypts, and wraps a validated document for both recipients.
    ///
    /// # Errors
    ///
    /// [`CryptoError::EntropyExhausted`] when randomness fails; nothing is produced.
    fn seal(&self, request: &SealRequest<'_>) -> Result<SealedEnvelope, CryptoError>;

    /// Parses and validates an envelope's structure and protected header without decrypting.
    fn inspect(&self, envelope: &[u8]) -> Result<EnvelopeHeader, CryptoError>;

    /// Decrypts and verifies an envelope for one reader, returning the canonical document.
    fn open(&self, envelope: &[u8], request: &OpenRequest<'_>) -> Result<Plaintext, CryptoError>;
}

/// Event integrity failures.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum IntegrityError {
    /// A signature or input is malformed.
    #[error("malformed")]
    Malformed,
    /// A signature does not verify.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The audit key is unusable.
    #[error("invariant")]
    Invariant,
}

/// Signs and verifies event hashes with the audit key, which is separate from wallet keys.
pub trait EventIntegrity: Send + Sync {
    /// Signs the bytes [`docchain_domain::event_signature_input`] returns.
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], IntegrityError>;

    /// Verifies a signature over those bytes.
    fn verify(&self, input: &[u8], signature: &[u8; 64]) -> Result<(), IntegrityError>;
}

/// Store failures, shared by the document and exchange stores.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    /// A uniqueness rule rejected the write.
    #[error("conflict")]
    Conflict,
    /// The item does not exist.
    #[error("not found")]
    NotFound,
    /// The relationship's pending limit is reached.
    #[error("pending limit")]
    PendingLimit,
    /// The store is temporarily unavailable.
    #[error("transient")]
    Transient,
    /// The store failed permanently.
    #[error("permanent")]
    Permanent,
    /// Stored data broke an invariant.
    #[error("invariant")]
    Invariant,
}

/// Holds ciphertext envelopes by opaque object ID. It never sees plaintext.
pub trait DocumentStore: Send + Sync {
    /// Proves the configured root can create, synchronize, and remove an object.
    fn probe_writable(&self) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Durably writes a new object; an existing object ID is a conflict.
    fn put_new(
        &self,
        object_id: &ObjectId,
        envelope: &[u8],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Reads an object.
    fn get(&self, object_id: &ObjectId)
    -> impl Future<Output = Result<Vec<u8>, StoreError>> + Send;

    /// Removes an object the caller has established no exchange references.
    fn remove(&self, object_id: &ObjectId) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// One committed exchange as stored. It holds no plaintext or plaintext digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeRecord {
    /// The exchange.
    pub exchange_id: ExchangeId,
    /// The sending wallet.
    pub sender: WalletId,
    /// The receiving wallet.
    pub recipient: WalletId,
    /// The document.
    pub document_id: DocumentId,
    /// The document version.
    pub document_version: DocumentVersion,
    /// The sender's request nonce.
    pub request_nonce: RequestNonce,
    /// The sender-scoped idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// The exact schema `$id`.
    pub schema_id: String,
    /// The exact schema version.
    pub schema_version: String,
    /// The stored ciphertext envelope.
    pub object_id: ObjectId,
    /// SHA-256 of the stored envelope.
    pub envelope_commitment: [u8; 32],
    /// SHA-256 of the protected header.
    pub protected_hash: [u8; 32],
    /// The envelope format version.
    pub envelope_version: u32,
    /// The key-registry sequence at which the bindings were checked.
    pub registry_sequence: u64,
    /// When the send read the clock and checked its keys. Reads judge historic key state at
    /// this time and `registry_sequence`.
    pub committed_at: Timestamp,
    /// Whether the recipient accepted it.
    pub accepted: bool,
}

/// How an acceptance commit ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptanceOutcome {
    /// This call recorded the acceptance and posted the credit.
    Recorded,
    /// The exchange was already accepted; nothing was written.
    AlreadyAccepted,
}

/// A balanced credit transaction: one debit from the issuance account, one credit to a wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditPosting {
    /// The unique key that makes the credit eligible at most once.
    pub eligibility_key: String,
    /// The credited wallet.
    pub wallet: WalletId,
    /// Credits posted; the debit posts the negation.
    pub amount: i64,
}

/// Persists exchanges, events, acceptances, and credits with transactional uniqueness.
pub trait ExchangeStore: Send + Sync {
    /// The sender's exchange for an idempotency key.
    fn find_by_idempotency(
        &self,
        sender: &WalletId,
        key: &IdempotencyKey,
    ) -> impl Future<Output = Result<Option<ExchangeRecord>, StoreError>> + Send;

    /// Whether the sender's nonce, or the document version for this recipient, is already used.
    fn replay_exists(
        &self,
        sender: &WalletId,
        nonce: &RequestNonce,
        document_id: &DocumentId,
        version: DocumentVersion,
        recipient: &WalletId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// One exchange.
    fn find(
        &self,
        exchange_id: &ExchangeId,
    ) -> impl Future<Output = Result<Option<ExchangeRecord>, StoreError>> + Send;

    /// Atomically enforces the pending limit and uniqueness, inserts the exchange, and appends
    /// its signed delivered event.
    fn commit_send<I: EventIntegrity>(
        &self,
        record: &ExchangeRecord,
        event: EventDraft,
        integrity: &I,
        pending_limit: u32,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Atomically records the acceptance, posts the balanced credit, and appends the signed
    /// accepted event, unless the exchange is already accepted.
    fn commit_acceptance<I: EventIntegrity>(
        &self,
        exchange_id: &ExchangeId,
        key: &IdempotencyKey,
        credit: &CreditPosting,
        event: EventDraft,
        integrity: &I,
    ) -> impl Future<Output = Result<AcceptanceOutcome, StoreError>> + Send;

    /// Pending exchanges addressed to a wallet, oldest first.
    fn pending_inbox(
        &self,
        wallet: &WalletId,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ExchangeId>, StoreError>> + Send;

    /// Events in sequence order.
    fn events(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AuditEvent>, StoreError>> + Send;

    /// Whether any exchange references an object.
    fn object_referenced(
        &self,
        object_id: &ObjectId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Whether the store is reachable.
    fn ping(&self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Supplies the current time.
pub trait Clock: Send + Sync {
    /// Now, to the second.
    fn now(&self) -> Timestamp;
}

/// The adapters one application instance uses, resolved statically.
pub trait Adapters: Send + Sync {
    /// Identity port.
    type Identity: Identity;
    /// Schema registry port.
    type Schemas: SchemaRegistry;
    /// Key registry port.
    type Keys: KeyRegistry;
    /// Envelope cryptography port.
    type Crypto: EnvelopeCryptography;
    /// Event integrity port.
    type Integrity: EventIntegrity;
    /// Document store port.
    type Documents: DocumentStore;
    /// Exchange store port.
    type Exchanges: ExchangeStore;
    /// Clock port.
    type Clock: Clock;

    /// The identity adapter.
    fn identity(&self) -> &Self::Identity;
    /// The schema registry adapter.
    fn schemas(&self) -> &Self::Schemas;
    /// The key registry adapter.
    fn keys(&self) -> &Self::Keys;
    /// The envelope cryptography adapter.
    fn crypto(&self) -> &Self::Crypto;
    /// The event integrity adapter.
    fn integrity(&self) -> &Self::Integrity;
    /// The document store adapter.
    fn documents(&self) -> &Self::Documents;
    /// The exchange store adapter.
    fn exchanges(&self) -> &Self::Exchanges;
    /// The clock adapter.
    fn clock(&self) -> &Self::Clock;
}
