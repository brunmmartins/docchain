//! Use-case tests over deterministic in-memory fakes of every port.
//!
//! The fake store enforces the same uniqueness rules, pending bound, and signed event chain the
//! port contract requires, so these tests observe orchestration and failure handling without
//! PostgreSQL, a filesystem, or real cryptography.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use docchain_domain::{
    AuditEvent, DocumentId, DocumentVersion, EventDraft, ExchangeId, RequestNonce, Timestamp,
    event_signature_input, parse_document,
};

use super::*;
use crate::ports::{
    Clock, DocumentStore, EnvelopeCryptography, EnvelopeHeader, EventIntegrity, ExchangeStore,
    Identity, IntegrityError, KeyRegistry, SchemaArtifact, SchemaRegistry, SealedEnvelope,
};

const SCHEMA_ID: &str = "urn:docchain:schema:service-application:1.0.0";
const SCHEMA: &[u8] = include_bytes!("../../../../schemas/service-application/1.0.0.schema.json");
const EXAMPLE: &[u8] = include_bytes!("../../../../schemas/service-application/example.json");
const SENDER: &str = "wal_0000000000000001";
const RECIPIENT: &str = "wal_0000000000000002";
const OTHER_SENDER: &str = "wal_0000000000000003";
const UNRELATED: &str = "wal_0000000000000004";
/// When the fake clock starts, and when every fixture key record takes effect.
const START: i64 = 1_790_000_000;
const KEYS_VALID_FROM: i64 = 1_700_000_000;

fn wallet(value: &str) -> WalletId {
    WalletId::new(value).expect("fixture wallet")
}

fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).expect("fixture idempotency key")
}

/// Envelopes the fake has sealed, by their bytes: the header and the plaintext they hold.
type SealedEnvelopes = HashMap<Vec<u8>, (EnvelopeHeader, Vec<u8>)>;

/// A key record's state in the fake registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordState {
    Active,
    Revoked,
}

/// One fake key record: key ID, registry sequence, the time it takes effect, and its state.
type KeyRecord = (String, u64, Timestamp, RecordState);

/// Every port, backed by shared in-memory state.
struct Fake {
    approved_digest: Mutex<[u8; 32]>,
    schema_bytes: Mutex<Vec<u8>>,
    bindings: Vec<VerifiedBinding>,
    /// Key records, append-only.
    key_records: Mutex<Vec<KeyRecord>>,
    /// Every historic key check: key ID, registry sequence, and time.
    effective_calls: Mutex<Vec<(String, u64, Timestamp)>>,
    /// A digest the historic check reports instead of the record's own.
    effective_digest: Mutex<Option<[u8; 32]>>,
    now: AtomicI64,
    entropy_fails: AtomicBool,
    seals: AtomicUsize,
    sealed: Mutex<SealedEnvelopes>,
    objects: Mutex<HashMap<ObjectId, Vec<u8>>>,
    object_reads: AtomicUsize,
    document_writable: AtomicBool,
    exchanges: Mutex<Vec<ExchangeRecord>>,
    acceptance_keys: Mutex<Vec<(WalletId, IdempotencyKey)>>,
    events: Mutex<Vec<AuditEvent>>,
    postings: Mutex<Vec<CreditPosting>>,
    /// How many upcoming replay lookups see the store as it was before a concurrent commit.
    stale_reads: AtomicUsize,
}

impl Fake {
    fn new() -> Self {
        let mut bindings = Vec::new();
        let mut key_records = Vec::new();
        for (index, (owner, purpose)) in [
            (SENDER, KeyPurpose::DocumentSigning),
            (SENDER, KeyPurpose::DocumentEncryption),
            (RECIPIENT, KeyPurpose::DocumentEncryption),
            (OTHER_SENDER, KeyPurpose::DocumentSigning),
            (OTHER_SENDER, KeyPurpose::DocumentEncryption),
        ]
        .into_iter()
        .enumerate()
        {
            let marker = u8::try_from(index).expect("small index");
            let sequence = u64::from(marker) + 1;
            let key_id = format!("key-{marker}");
            key_records.push((
                key_id.clone(),
                sequence,
                Timestamp::from_unix_seconds(KEYS_VALID_FROM),
                RecordState::Active,
            ));
            bindings.push(VerifiedBinding {
                wallet: wallet(owner),
                purpose,
                key_id,
                public_key: [marker; 32],
                binding_digest: [marker.wrapping_add(100); 32],
                sequence,
            });
        }
        let schema = parse_document(SCHEMA).expect("approved schema");
        Self {
            approved_digest: Mutex::new(sha256(schema.bytes())),
            schema_bytes: Mutex::new(SCHEMA.to_vec()),
            bindings,
            key_records: Mutex::new(key_records),
            effective_calls: Mutex::new(Vec::new()),
            effective_digest: Mutex::new(None),
            now: AtomicI64::new(START),
            entropy_fails: AtomicBool::new(false),
            seals: AtomicUsize::new(0),
            sealed: Mutex::new(HashMap::new()),
            objects: Mutex::new(HashMap::new()),
            object_reads: AtomicUsize::new(0),
            document_writable: AtomicBool::new(true),
            exchanges: Mutex::new(Vec::new()),
            acceptance_keys: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            postings: Mutex::new(Vec::new()),
            stale_reads: AtomicUsize::new(0),
        }
    }

    fn stale(&self) -> bool {
        self.stale_reads
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
    }

    /// The rule both key lookups share: among the key's records up to `sequence`, the one with
    /// the highest sequence already in effect at `at` decides.
    fn effective(
        &self,
        key_id: &str,
        sequence: u64,
        at: Timestamp,
    ) -> Result<VerifiedBinding, KeyRegistryError> {
        let records = self.key_records.lock().expect("key records");
        let known = records
            .iter()
            .filter(|(id, recorded, _, _)| id == key_id && *recorded <= sequence)
            .collect::<Vec<_>>();
        if known.is_empty() {
            return Err(KeyRegistryError::NotFound);
        }
        let (_, _, _, state) = known
            .into_iter()
            .filter(|(_, _, from, _)| *from <= at)
            .max_by_key(|(_, recorded, _, _)| *recorded)
            .ok_or(KeyRegistryError::Inactive)?;
        if *state == RecordState::Revoked {
            return Err(KeyRegistryError::Revoked);
        }
        self.bindings
            .iter()
            .find(|binding| binding.key_id == key_id)
            .cloned()
            .ok_or(KeyRegistryError::NotFound)
    }

    fn object_count(&self) -> usize {
        self.objects.lock().expect("objects").len()
    }

    fn event_count(&self) -> usize {
        self.events.lock().expect("events").len()
    }

    fn append(&self, draft: EventDraft, integrity: &impl EventIntegrity) -> Result<(), StoreError> {
        let mut events = self.events.lock().expect("events");
        let previous = events.last().map_or([0; 32], |event| event.event_hash);
        let sequence = u64::try_from(events.len()).map_err(|_| StoreError::Invariant)? + 1;
        let hash =
            AuditEvent::hash_for(&draft, sequence, &previous).map_err(|_| StoreError::Invariant)?;
        let signature = integrity
            .sign(&event_signature_input(&hash))
            .map_err(|_| StoreError::Invariant)?;
        events.push(
            AuditEvent::assemble(draft, sequence, previous, signature)
                .map_err(|_| StoreError::Invariant)?,
        );
        Ok(())
    }
}

impl Identity for Fake {
    async fn authenticate(&self, credential: &Credential) -> Result<Actor, IdentityError> {
        match credential.expose() {
            "sender" => Ok(Actor::Wallet(wallet(SENDER))),
            "auditor" => Ok(Actor::Auditor),
            _ => Err(IdentityError::Unauthorized),
        }
    }
}

impl SchemaRegistry for Fake {
    async fn load_active(
        &self,
        schema_id: &str,
        version: &str,
    ) -> Result<SchemaArtifact, SchemaRegistryError> {
        if schema_id != SCHEMA_ID || version != "1.0.0" {
            return Err(SchemaRegistryError::NotFound);
        }
        Ok(SchemaArtifact {
            id: schema_id.to_owned(),
            version: version.to_owned(),
            bytes: self.schema_bytes.lock().expect("schema bytes").clone(),
            approved_digest: *self.approved_digest.lock().expect("digest"),
        })
    }
}

impl KeyRegistry for Fake {
    async fn resolve_active(
        &self,
        owner: &WalletId,
        purpose: KeyPurpose,
        at: Timestamp,
    ) -> Result<VerifiedBinding, KeyRegistryError> {
        let binding = self
            .bindings
            .iter()
            .find(|binding| binding.wallet == *owner && binding.purpose == purpose)
            .ok_or(KeyRegistryError::NotFound)?;
        let head = self.head_sequence().await?;
        self.effective(&binding.key_id, head, at)
    }

    async fn load(&self, binding_digest: &[u8; 32]) -> Result<VerifiedBinding, KeyRegistryError> {
        self.bindings
            .iter()
            .find(|binding| binding.binding_digest == *binding_digest)
            .cloned()
            .ok_or(KeyRegistryError::NotFound)
    }

    async fn effective_as_of(
        &self,
        key_id: &str,
        sequence: u64,
        at: Timestamp,
    ) -> Result<VerifiedBinding, KeyRegistryError> {
        self.effective_calls.lock().expect("effective calls").push((
            key_id.to_owned(),
            sequence,
            at,
        ));
        let mut binding = self.effective(key_id, sequence, at)?;
        if let Some(digest) = *self.effective_digest.lock().expect("effective digest") {
            binding.binding_digest = digest;
        }
        Ok(binding)
    }

    async fn head_sequence(&self) -> Result<u64, KeyRegistryError> {
        self.key_records
            .lock()
            .expect("key records")
            .last()
            .map(|(_, sequence, _, _)| *sequence)
            .ok_or(KeyRegistryError::NotFound)
    }
}

fn header_key(binding: &VerifiedBinding) -> HeaderKey {
    HeaderKey {
        wallet: binding.wallet.clone(),
        key_id: binding.key_id.clone(),
        binding_digest: binding.binding_digest,
    }
}

impl EnvelopeCryptography for Fake {
    fn seal(&self, request: &SealRequest<'_>) -> Result<SealedEnvelope, CryptoError> {
        if self.entropy_fails.load(Ordering::SeqCst) {
            return Err(CryptoError::EntropyExhausted);
        }
        // Fresh randomness makes every sealing distinct, even of the same request.
        let serial = self.seals.fetch_add(1, Ordering::SeqCst);
        let bytes = format!("sealed-envelope-{serial}").into_bytes();
        let header = EnvelopeHeader {
            envelope_version: 1,
            protected_hash: sha256(&bytes),
            document_id: request.document_id.clone(),
            document_version: request.document_version,
            schema_id: request.schema_id.to_owned(),
            schema_digest: request.schema_digest,
            sender: header_key(request.sender_signing),
            recipients: request.recipients.iter().map(|b| header_key(b)).collect(),
        };
        self.sealed
            .lock()
            .expect("sealed")
            .insert(bytes.clone(), (header, request.canonical_document.to_vec()));
        Ok(SealedEnvelope {
            commitment: envelope_commitment(&bytes),
            protected_hash: sha256(&bytes),
            envelope_version: 1,
            bytes,
        })
    }

    fn inspect(&self, envelope: &[u8]) -> Result<EnvelopeHeader, CryptoError> {
        self.sealed
            .lock()
            .expect("sealed")
            .get(envelope)
            .map(|(header, _)| header.clone())
            .ok_or(CryptoError::InvalidInput)
    }

    fn open(&self, envelope: &[u8], request: &OpenRequest<'_>) -> Result<Plaintext, CryptoError> {
        let sealed = self.sealed.lock().expect("sealed");
        let (header, plaintext) = sealed.get(envelope).ok_or(CryptoError::InvalidInput)?;
        if header != request.header
            || header.sender != header_key(request.sender_signing)
            || !header.recipients.contains(&header_key(request.reader))
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Plaintext::new(plaintext.clone()))
    }
}

impl EventIntegrity for Fake {
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], IntegrityError> {
        let first = sha256(&[b"fake-audit-key".as_slice(), input].concat());
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&first);
        signature[32..].copy_from_slice(&sha256(&first));
        Ok(signature)
    }

    fn verify(&self, input: &[u8], signature: &[u8; 64]) -> Result<(), IntegrityError> {
        (self.sign(input)? == *signature)
            .then_some(())
            .ok_or(IntegrityError::AuthenticationFailed)
    }
}

impl DocumentStore for Fake {
    async fn probe_writable(&self) -> Result<(), StoreError> {
        self.document_writable
            .load(Ordering::SeqCst)
            .then_some(())
            .ok_or(StoreError::Permanent)
    }

    async fn put_new(&self, object_id: &ObjectId, envelope: &[u8]) -> Result<(), StoreError> {
        let mut objects = self.objects.lock().expect("objects");
        if objects.contains_key(object_id) {
            return Err(StoreError::Conflict);
        }
        objects.insert(object_id.clone(), envelope.to_vec());
        Ok(())
    }

    async fn get(&self, object_id: &ObjectId) -> Result<Vec<u8>, StoreError> {
        self.object_reads.fetch_add(1, Ordering::SeqCst);
        self.objects
            .lock()
            .expect("objects")
            .get(object_id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn remove(&self, object_id: &ObjectId) -> Result<(), StoreError> {
        self.objects.lock().expect("objects").remove(object_id);
        Ok(())
    }
}

impl ExchangeStore for Fake {
    async fn find_by_idempotency(
        &self,
        sender: &WalletId,
        idempotency: &IdempotencyKey,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        if self.stale() {
            return Ok(None);
        }
        Ok(self
            .exchanges
            .lock()
            .expect("exchanges")
            .iter()
            .find(|record| record.sender == *sender && record.idempotency_key == *idempotency)
            .cloned())
    }

    async fn replay_exists(
        &self,
        sender: &WalletId,
        nonce: &RequestNonce,
        document_id: &DocumentId,
        version: DocumentVersion,
        recipient: &WalletId,
    ) -> Result<bool, StoreError> {
        if self.stale() {
            return Ok(false);
        }
        Ok(self
            .exchanges
            .lock()
            .expect("exchanges")
            .iter()
            .any(|record| {
                (record.sender == *sender && record.request_nonce == *nonce)
                    || (record.sender == *sender
                        && record.document_id == *document_id
                        && record.document_version == version
                        && record.recipient == *recipient)
            }))
    }

    async fn find(&self, exchange_id: &ExchangeId) -> Result<Option<ExchangeRecord>, StoreError> {
        Ok(self
            .exchanges
            .lock()
            .expect("exchanges")
            .iter()
            .find(|record| record.exchange_id == *exchange_id)
            .cloned())
    }

    async fn commit_send<I: EventIntegrity>(
        &self,
        record: &ExchangeRecord,
        event: EventDraft,
        integrity: &I,
        pending_limit: u32,
    ) -> Result<(), StoreError> {
        let mut exchanges = self.exchanges.lock().expect("exchanges");
        let pending = exchanges
            .iter()
            .filter(|other| {
                other.sender == record.sender
                    && other.recipient == record.recipient
                    && !other.accepted
            })
            .count();
        if pending >= usize::try_from(pending_limit).map_err(|_| StoreError::Invariant)? {
            return Err(StoreError::PendingLimit);
        }
        let conflict = exchanges.iter().any(|other| {
            other.exchange_id == record.exchange_id
                || other.object_id == record.object_id
                || (other.sender == record.sender
                    && (other.idempotency_key == record.idempotency_key
                        || other.request_nonce == record.request_nonce))
                || (other.sender == record.sender
                    && other.document_id == record.document_id
                    && other.document_version == record.document_version
                    && other.recipient == record.recipient)
        });
        if conflict {
            return Err(StoreError::Conflict);
        }
        self.append(event, integrity)?;
        exchanges.push(record.clone());
        Ok(())
    }

    async fn commit_acceptance<I: EventIntegrity>(
        &self,
        exchange_id: &ExchangeId,
        idempotency: &IdempotencyKey,
        credit: &CreditPosting,
        event: EventDraft,
        integrity: &I,
    ) -> Result<AcceptanceOutcome, StoreError> {
        let mut exchanges = self.exchanges.lock().expect("exchanges");
        let record = exchanges
            .iter_mut()
            .find(|record| record.exchange_id == *exchange_id)
            .ok_or(StoreError::NotFound)?;
        if record.accepted {
            return Ok(AcceptanceOutcome::AlreadyAccepted);
        }
        let mut keys = self.acceptance_keys.lock().expect("acceptance keys");
        let scoped = (record.recipient.clone(), idempotency.clone());
        if keys.contains(&scoped) {
            return Err(StoreError::Conflict);
        }
        let mut postings = self.postings.lock().expect("postings");
        if postings
            .iter()
            .any(|posting| posting.eligibility_key == credit.eligibility_key)
        {
            return Err(StoreError::Conflict);
        }
        self.append(event, integrity)?;
        keys.push(scoped);
        postings.push(credit.clone());
        record.accepted = true;
        Ok(AcceptanceOutcome::Recorded)
    }

    async fn pending_inbox(
        &self,
        owner: &WalletId,
        limit: u32,
    ) -> Result<Vec<ExchangeId>, StoreError> {
        Ok(self
            .exchanges
            .lock()
            .expect("exchanges")
            .iter()
            .filter(|record| record.recipient == *owner && !record.accepted)
            .take(usize::try_from(limit).map_err(|_| StoreError::Invariant)?)
            .map(|record| record.exchange_id.clone())
            .collect())
    }

    async fn events(&self, limit: u32) -> Result<Vec<AuditEvent>, StoreError> {
        Ok(self
            .events
            .lock()
            .expect("events")
            .iter()
            .take(usize::try_from(limit).map_err(|_| StoreError::Invariant)?)
            .cloned()
            .collect())
    }

    async fn object_referenced(&self, object_id: &ObjectId) -> Result<bool, StoreError> {
        Ok(self
            .exchanges
            .lock()
            .expect("exchanges")
            .iter()
            .any(|record| record.object_id == *object_id))
    }

    async fn ping(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

impl Clock for Fake {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_seconds(self.now.load(Ordering::SeqCst))
    }
}

struct Fakes(Fake);

impl Adapters for Fakes {
    type Identity = Fake;
    type Schemas = Fake;
    type Keys = Fake;
    type Crypto = Fake;
    type Integrity = Fake;
    type Documents = Fake;
    type Exchanges = Fake;
    type Clock = Fake;

    fn identity(&self) -> &Fake {
        &self.0
    }
    fn schemas(&self) -> &Fake {
        &self.0
    }
    fn keys(&self) -> &Fake {
        &self.0
    }
    fn crypto(&self) -> &Fake {
        &self.0
    }
    fn integrity(&self) -> &Fake {
        &self.0
    }
    fn documents(&self) -> &Fake {
        &self.0
    }
    fn exchanges(&self) -> &Fake {
        &self.0
    }
    fn clock(&self) -> &Fake {
        &self.0
    }
}

fn application() -> Application<Fakes> {
    application_with(Limits::default())
}

fn application_with(limits: Limits) -> Application<Fakes> {
    Application::new(Fakes(Fake::new()), limits)
}

fn fake(application: &Application<Fakes>) -> &Fake {
    &application.adapters().0
}

fn actor(value: &str) -> Actor {
    Actor::Wallet(wallet(value))
}

fn command() -> SendCopyCommand {
    SendCopyCommand {
        sender: wallet(SENDER),
        recipient: wallet(RECIPIENT),
        document_id: DocumentId::new("doc_0000000000000001").expect("document"),
        document_version: DocumentVersion::new(1).expect("version"),
        request_nonce: RequestNonce::new([7; 16]),
        idempotency_key: key("idem_0000000000000001"),
        schema_id: SCHEMA_ID.to_owned(),
        schema_version: "1.0.0".to_owned(),
        document: EXAMPLE.to_vec(),
    }
}

fn canonical_example() -> Vec<u8> {
    parse_document(EXAMPLE).expect("example").bytes().to_vec()
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn authenticates_through_the_identity_port_only() {
    let application = application();
    let credential = |value: &str| Credential::new(value.to_owned());
    assert_eq!(
        block_on(application.authenticate(&credential("sender"))),
        Ok(actor(SENDER))
    );
    assert_eq!(
        block_on(application.authenticate(&credential(SENDER))),
        Err(ApplicationError::Unauthenticated)
    );
}

#[test]
fn send_copy_commits_one_signed_event_readable_by_both_participants() {
    let application = application();
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    let fake = fake(&application);

    assert_eq!((fake.object_count(), fake.event_count()), (1, 1));
    let events = fake.events.lock().expect("events").clone();
    assert_eq!(events[0].draft.kind, EventKind::Delivered);
    assert_eq!(
        events[0].draft.envelope_commitment,
        delivery.envelope_commitment
    );
    for reader in [SENDER, RECIPIENT] {
        let plaintext = block_on(application.read_document(&actor(reader), &delivery.exchange_id))
            .expect("participant copy");
        assert_eq!(plaintext.as_bytes(), canonical_example());
    }
    assert_eq!(
        block_on(application.list_inbox(&actor(RECIPIENT), &wallet(RECIPIENT))),
        Ok(vec![delivery.exchange_id])
    );
}

#[test]
fn send_copy_refuses_anyone_but_the_sender_before_any_work() {
    let application = application();
    for caller in [
        actor(RECIPIENT),
        actor(UNRELATED),
        Actor::Operator,
        Actor::Auditor,
    ] {
        assert_eq!(
            block_on(application.send_copy(&caller, command())),
            Err(ApplicationError::Forbidden)
        );
    }
    let mut to_self = command();
    to_self.recipient = wallet(SENDER);
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), to_self)),
        Err(ApplicationError::InvalidRequest)
    );
    let fake = fake(&application);
    assert_eq!(
        (
            fake.seals.load(Ordering::SeqCst),
            fake.object_count(),
            fake.event_count()
        ),
        (0, 0, 0)
    );
}

#[test]
fn send_copy_rejects_invalid_or_unapproved_documents_before_sealing() {
    let application = application();
    let mut invalid = command();
    invalid.document = br#"{"applicationReference":"SYN-APP0001"}"#.to_vec();
    let mut duplicate = command();
    duplicate.document = br#"{"statement":"a","statement":"b"}"#.to_vec();
    let mut unknown = command();
    unknown.schema_version = "2.0.0".to_owned();
    for (case, request, expected) in [
        ("schema-invalid", invalid, ApplicationError::InvalidDocument),
        (
            "duplicate member",
            duplicate,
            ApplicationError::InvalidDocument,
        ),
        (
            "unknown schema",
            unknown,
            ApplicationError::UnsupportedSchema,
        ),
    ] {
        assert_eq!(
            block_on(application.send_copy(&actor(SENDER), request)),
            Err(expected),
            "{case}"
        );
    }

    // An artifact whose recomputed digest differs from the approved one is never used.
    *fake(&application).approved_digest.lock().expect("digest") = [0; 32];
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Err(ApplicationError::UnsupportedSchema)
    );
    let fake = fake(&application);
    assert_eq!(
        (
            fake.seals.load(Ordering::SeqCst),
            fake.object_count(),
            fake.event_count()
        ),
        (0, 0, 0)
    );
}

#[test]
fn unsupported_schema_fails_before_any_write() {
    let application = application();
    let mut artifact = parse_document(SCHEMA).expect("schema").value().clone();
    artifact.as_object_mut().expect("schema object").insert(
        "oneOf".to_owned(),
        parse_document(b"[]").expect("array").value().clone(),
    );
    let bytes = docchain_domain::canonicalize(&artifact).expect("canonical schema");
    let fake = fake(&application);
    *fake.approved_digest.lock().expect("digest") = sha256(&bytes);
    *fake.schema_bytes.lock().expect("schema bytes") = bytes;

    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Err(ApplicationError::UnsupportedSchema)
    );
    assert_eq!((fake.object_count(), fake.event_count()), (0, 0));
    assert!(fake.exchanges.lock().expect("exchanges").is_empty());
}

#[test]
fn served_bytes_must_match_the_approved_digest() {
    let application = application();
    // A substituted artifact that is still a valid, compilable schema; only its digest differs.
    let substituted = String::from_utf8(SCHEMA.to_vec())
        .expect("UTF-8 schema")
        .replace("\"maxLength\": 2000", "\"maxLength\": 2001");
    assert_ne!(substituted.as_bytes(), SCHEMA);
    *fake(&application)
        .schema_bytes
        .lock()
        .expect("schema bytes") = substituted.into_bytes();
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Err(ApplicationError::UnsupportedSchema)
    );
    let fake = fake(&application);
    assert_eq!((fake.object_count(), fake.event_count()), (0, 0));
}

#[test]
fn approved_bytes_under_another_digest_are_rejected() {
    let application = application();
    *fake(&application).approved_digest.lock().expect("digest") = [0x55; 32];
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Err(ApplicationError::UnsupportedSchema)
    );
    let fake = fake(&application);
    assert_eq!((fake.object_count(), fake.event_count()), (0, 0));
}

#[test]
fn ready_requires_a_writable_document_store() {
    let application = application();
    assert_eq!(block_on(application.ready()), Ok(()));
    fake(&application)
        .document_writable
        .store(false, Ordering::SeqCst);
    assert_eq!(
        block_on(application.ready()),
        Err(ApplicationError::Unavailable)
    );
}

#[test]
fn send_copy_returns_the_prior_result_only_for_the_same_senders_same_request() {
    let application = application();
    let first = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Ok(first.clone())
    );

    let mut changed_document = command();
    changed_document.document = EXAMPLE
        .to_vec()
        .iter()
        .map(|byte| if *byte == b'P' { b'Q' } else { *byte })
        .collect();
    let mut changed_recipient = command();
    changed_recipient.recipient = wallet(UNRELATED);
    let mut reused_nonce = command();
    reused_nonce.idempotency_key = key("idem_0000000000000002");
    reused_nonce.document_id = DocumentId::new("doc_0000000000000002").expect("document");
    let mut reused_version = command();
    reused_version.idempotency_key = key("idem_0000000000000003");
    reused_version.request_nonce = RequestNonce::new([8; 16]);
    for (case, request) in [
        ("same key, other document", changed_document),
        ("same key, other recipient", changed_recipient),
        ("reused nonce", reused_nonce),
        ("reused document version for recipient", reused_version),
    ] {
        assert_eq!(
            block_on(application.send_copy(&actor(SENDER), request)),
            Err(ApplicationError::Replay),
            "{case}"
        );
    }

    // Idempotency keys belong to their sender: another wallet's identical key is its own request.
    let mut other_sender = command();
    other_sender.sender = wallet(OTHER_SENDER);
    other_sender.document_id = DocumentId::new("doc_0000000000000003").expect("document");
    let other = block_on(application.send_copy(&actor(OTHER_SENDER), other_sender))
        .expect("independent delivery");
    assert_ne!(other.exchange_id, first.exchange_id);
    let fake = fake(&application);
    assert_eq!((fake.object_count(), fake.event_count()), (2, 2));
}

#[test]
fn replay_check_is_scoped_to_the_sender() {
    let application = application();
    // Another sender claims the same document, version, recipient, nonce, and key first.
    let mut pre_claim = command();
    pre_claim.sender = wallet(OTHER_SENDER);
    let other = block_on(application.send_copy(&actor(OTHER_SENDER), pre_claim.clone()))
        .expect("the other sender's delivery");

    let own = block_on(application.send_copy(&actor(SENDER), command()))
        .expect("another sender's tuple is never a replay");
    assert_ne!(own.exchange_id, other.exchange_id);

    // Each sender's own tuple is still refused when reused under a fresh request.
    for (sender, mut request) in [(SENDER, command()), (OTHER_SENDER, pre_claim)] {
        request.idempotency_key = key("idem_0000000000000009");
        request.request_nonce = RequestNonce::new([9; 16]);
        assert_eq!(
            block_on(application.send_copy(&actor(sender), request)),
            Err(ApplicationError::Replay),
            "{sender}"
        );
    }
    let fake = fake(&application);
    assert_eq!((fake.object_count(), fake.event_count()), (2, 2));
}

#[test]
fn acceptance_result_names_only_the_exchange() {
    let application = application();
    let first = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    let mut second = command();
    second.idempotency_key = key("idem_0000000000000002");
    second.request_nonce = RequestNonce::new([8; 16]);
    second.document_version = DocumentVersion::new(2).expect("version");
    let second = block_on(application.send_copy(&actor(SENDER), second)).expect("delivery");

    for (delivery, acceptance_key) in [
        (&first, "idem_accept0000000001"),
        (&second, "idem_accept0000000002"),
    ] {
        let accepted = block_on(application.accept(
            &actor(RECIPIENT),
            &delivery.exchange_id,
            &key(acceptance_key),
        ))
        .expect("acceptance");
        // The sender's balance is now two, but each result reports only its own award.
        assert_eq!(
            accepted,
            AcceptanceResult {
                exchange_id: delivery.exchange_id.clone(),
                credit_awarded: 1,
            }
        );
    }
    assert_eq!(
        fake(&application).postings.lock().expect("postings").len(),
        2
    );
}

#[test]
fn concurrent_duplicate_send_returns_the_winner_and_discards_its_own_object() {
    let application = application();
    let winner = block_on(application.send_copy(&actor(SENDER), command())).expect("winner");
    // The loser read the store before the winner committed, so both replay checks pass.
    fake(&application).stale_reads.store(2, Ordering::SeqCst);
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Ok(winner)
    );
    let fake = fake(&application);
    assert_eq!(fake.seals.load(Ordering::SeqCst), 2);
    assert_eq!((fake.object_count(), fake.event_count()), (1, 1));
}

#[test]
fn duplicate_send_committed_between_its_replay_reads_returns_the_prior_result() {
    let application = application();
    let winner = block_on(application.send_copy(&actor(SENDER), command())).expect("winner");
    // Only the idempotency lookup predates the winner's commit; the nonce check sees it.
    fake(&application).stale_reads.store(1, Ordering::SeqCst);
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Ok(winner)
    );
    let fake = fake(&application);
    assert_eq!(fake.seals.load(Ordering::SeqCst), 1);
    assert_eq!((fake.object_count(), fake.event_count()), (1, 1));
}

#[test]
fn send_copy_stops_at_the_pending_limit_and_discards_the_object() {
    let application = application_with(Limits {
        pending_per_relationship: 1,
        ..Limits::default()
    });
    block_on(application.send_copy(&actor(SENDER), command())).expect("first pending");
    let mut second = command();
    second.idempotency_key = key("idem_0000000000000002");
    second.request_nonce = RequestNonce::new([8; 16]);
    second.document_version = DocumentVersion::new(2).expect("version");
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), second)),
        Err(ApplicationError::PendingLimit)
    );
    let fake = fake(&application);
    assert_eq!((fake.object_count(), fake.event_count()), (1, 1));
}

#[test]
fn entropy_failure_commits_no_object_or_event() {
    let application = application();
    fake(&application)
        .entropy_fails
        .store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Err(ApplicationError::Unavailable)
    );
    let fake = fake(&application);
    assert_eq!((fake.object_count(), fake.event_count()), (0, 0));
    assert!(fake.exchanges.lock().expect("exchanges").is_empty());
}

#[test]
fn acceptance_credits_the_sender_once_and_only_for_the_recipient() {
    let application = application();
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    let exchange = delivery.exchange_id;
    let unknown = ExchangeId::new("exc_00000000000000000000000000000000").expect("id");
    for (caller, target) in [
        (actor(SENDER), &exchange),
        (actor(UNRELATED), &exchange),
        (Actor::Operator, &exchange),
        (actor(RECIPIENT), &unknown),
    ] {
        assert_eq!(
            block_on(application.accept(&caller, target, &key("idem_accept0000000001"))),
            Err(ApplicationError::Forbidden)
        );
    }

    let accepted =
        block_on(application.accept(&actor(RECIPIENT), &exchange, &key("idem_accept0000000001")))
            .expect("acceptance");
    assert_eq!(accepted.credit_awarded, 1);
    let again =
        block_on(application.accept(&actor(RECIPIENT), &exchange, &key("idem_accept0000000002")));
    assert_eq!(again, Ok(accepted));
    let fake_state = fake(&application);
    assert_eq!(fake_state.event_count(), 2);
    let postings = fake_state.postings.lock().expect("postings").clone();
    assert_eq!(postings.len(), 1);
    assert_eq!(
        (postings[0].wallet.clone(), postings[0].amount),
        (wallet(SENDER), 1)
    );

    // The recipient's acceptance key is spent, even for another exchange.
    let mut second = command();
    second.idempotency_key = key("idem_0000000000000002");
    second.request_nonce = RequestNonce::new([8; 16]);
    second.document_version = DocumentVersion::new(2).expect("version");
    let second = block_on(application.send_copy(&actor(SENDER), second)).expect("delivery");
    assert_eq!(
        block_on(application.accept(
            &actor(RECIPIENT),
            &second.exchange_id,
            &key("idem_accept0000000001"),
        )),
        Err(ApplicationError::Replay)
    );
}

#[test]
fn reads_and_listings_are_limited_to_participants() {
    let application = application();
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    let unknown = ExchangeId::new("exc_00000000000000000000000000000000").expect("id");
    for caller in [actor(UNRELATED), Actor::Operator, Actor::Auditor] {
        for exchange in [&delivery.exchange_id, &unknown] {
            assert_eq!(
                block_on(application.read_document(&caller, exchange)).map(|_| ()),
                Err(ApplicationError::Forbidden)
            );
        }
        assert_eq!(
            block_on(application.list_inbox(&caller, &wallet(RECIPIENT))),
            Err(ApplicationError::Forbidden)
        );
    }
    // Authorization happens before any ciphertext is fetched.
    assert_eq!(fake(&application).object_reads.load(Ordering::SeqCst), 0);
}

#[test]
fn reads_reject_substituted_envelopes_and_keys_revoked_before_commit() {
    let application = application();
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    let fake_state = fake(&application);

    // A revocation recorded after the commit does not reach back to the committed exchange.
    let recipient_key = fake_state.bindings[2].key_id.clone();
    fake_state.key_records.lock().expect("key records").push((
        recipient_key,
        10,
        Timestamp::from_unix_seconds(KEYS_VALID_FROM),
        RecordState::Revoked,
    ));
    assert!(block_on(application.read_document(&actor(RECIPIENT), &delivery.exchange_id)).is_ok());

    // An exchange claiming a registry sequence at which its key was revoked does not open.
    fake_state
        .exchanges
        .lock()
        .expect("exchanges")
        .iter_mut()
        .for_each(|record| record.registry_sequence = 10);
    assert_eq!(
        block_on(application.read_document(&actor(RECIPIENT), &delivery.exchange_id)).map(|_| ()),
        Err(ApplicationError::InvalidEnvelope)
    );
    fake_state
        .exchanges
        .lock()
        .expect("exchanges")
        .iter_mut()
        .for_each(|record| record.registry_sequence = 5);

    // Ciphertext substituted in the document store does not match the committed commitment.
    fake_state
        .objects
        .lock()
        .expect("objects")
        .insert(delivery.object_id.clone(), b"substituted".to_vec());
    assert_eq!(
        block_on(application.read_document(&actor(SENDER), &delivery.exchange_id)).map(|_| ()),
        Err(ApplicationError::InvalidEnvelope)
    );
}

#[test]
fn audit_verifies_events_and_ciphertext_for_auditors_only() {
    let application = application();
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    block_on(application.accept(
        &actor(RECIPIENT),
        &delivery.exchange_id,
        &key("idem_accept0000000001"),
    ))
    .expect("acceptance");
    for caller in [actor(SENDER), actor(RECIPIENT), Actor::Operator] {
        assert_eq!(
            block_on(application.verify_audit(&caller, None)),
            Err(ApplicationError::Forbidden)
        );
    }
    let report = block_on(application.verify_audit(&Actor::Auditor, None)).expect("verified");
    assert_eq!(report.event_count, 2);
    let head = report.head.expect("head");

    let fake_state = fake(&application);
    let removed = fake_state
        .events
        .lock()
        .expect("events")
        .pop()
        .expect("event");
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, Some(head))),
        Err(ApplicationError::IntegrityFailure)
    );
    fake_state.events.lock().expect("events").push(removed);
    assert!(block_on(application.verify_audit(&Actor::Auditor, Some(head))).is_ok());

    fake_state
        .objects
        .lock()
        .expect("objects")
        .insert(delivery.object_id, b"substituted".to_vec());
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::IntegrityFailure)
    );
}

#[test]
fn audit_beyond_the_event_limit_is_incomplete_without_a_head() {
    let application = application_with(Limits {
        audit_events: 3,
        ..Limits::default()
    });
    let mut exchanges = Vec::new();
    for (index, version) in [(1_u8, 1_u64), (2, 2)] {
        let mut request = command();
        request.idempotency_key = key(&format!("idem_000000000000000{index}"));
        request.request_nonce = RequestNonce::new([index; 16]);
        request.document_version = DocumentVersion::new(version).expect("version");
        exchanges.push(
            block_on(application.send_copy(&actor(SENDER), request))
                .expect("delivery")
                .exchange_id,
        );
    }
    block_on(application.accept(
        &actor(RECIPIENT),
        &exchanges[0],
        &key("idem_accept0000000001"),
    ))
    .expect("acceptance");
    assert_eq!(fake(&application).event_count(), 3);
    assert!(block_on(application.verify_audit(&Actor::Auditor, None)).is_ok());

    block_on(application.accept(
        &actor(RECIPIENT),
        &exchanges[1],
        &key("idem_accept0000000002"),
    ))
    .expect("acceptance");
    assert_eq!(fake(&application).event_count(), 4);
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditIncomplete)
    );
}

#[test]
fn read_after_a_scheduled_revocation_is_judged_at_the_commit_time() {
    let application = application();
    let fake_state = fake(&application);
    let sent_at = Timestamp::from_unix_seconds(START);
    let revoked_from = Timestamp::from_unix_seconds(START + 60);
    let recipient_key = fake_state.bindings[2].key_id.clone();
    fake_state.key_records.lock().expect("key records").push((
        recipient_key,
        10,
        revoked_from,
        RecordState::Revoked,
    ));

    let delivery = block_on(application.send_copy(&actor(SENDER), command()))
        .expect("a send before the revocation takes effect");
    let record = fake_state.exchanges.lock().expect("exchanges")[0].clone();
    assert_eq!(
        (record.committed_at, record.registry_sequence),
        (sent_at, 10)
    );
    assert_eq!(
        fake_state.events.lock().expect("events")[0]
            .draft
            .committed_at,
        sent_at
    );

    fake_state.now.store(START + 61, Ordering::SeqCst);
    fake_state
        .effective_calls
        .lock()
        .expect("effective calls")
        .clear();
    for reader in [SENDER, RECIPIENT] {
        let plaintext = block_on(application.read_document(&actor(reader), &delivery.exchange_id))
            .expect("the key was in force when the copy was sent");
        assert_eq!(plaintext.as_bytes(), canonical_example(), "{reader}");
    }
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), command())),
        Ok(delivery.clone()),
        "an identical replay returns the prior delivery"
    );
    let mut later = command();
    later.idempotency_key = key("idem_0000000000000002");
    later.request_nonce = RequestNonce::new([8; 16]);
    later.document_version = DocumentVersion::new(2).expect("version");
    assert_eq!(
        block_on(application.send_copy(&actor(SENDER), later)).map(|_| ()),
        Err(ApplicationError::KeyBinding),
        "a new send after the revocation takes effect"
    );
    let calls = fake_state
        .effective_calls
        .lock()
        .expect("effective calls")
        .clone();
    assert!(!calls.is_empty());
    assert!(
        calls
            .iter()
            .all(|(_, sequence, at)| (*sequence, *at) == (10, sent_at)),
        "{calls:?}"
    );

    // A stored commit time at the revocation's effective time does not open.
    let set_committed_at = |at: Timestamp| {
        fake_state
            .exchanges
            .lock()
            .expect("exchanges")
            .iter_mut()
            .for_each(|record| record.committed_at = at);
    };
    set_committed_at(revoked_from);
    assert_eq!(
        block_on(application.read_document(&actor(RECIPIENT), &delivery.exchange_id)).map(|_| ()),
        Err(ApplicationError::InvalidEnvelope)
    );
    set_committed_at(sent_at);

    // Nor does a key whose record in force is not the one the header pins.
    *fake_state
        .effective_digest
        .lock()
        .expect("effective digest") = Some([0xee; 32]);
    assert_eq!(
        block_on(application.read_document(&actor(RECIPIENT), &delivery.exchange_id)).map(|_| ()),
        Err(ApplicationError::InvalidEnvelope)
    );
}
