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
    AuditChallenge, AuditEvent, AuditExportManifest, AuditSnapshot, CreditLedgerEntry,
    CreditLedgerTransaction, DocumentId, DocumentVersion, EventDraft, ExchangeId, ISSUANCE_ACCOUNT,
    RequestNonce, Timestamp, event_signature_input, parse_document,
};

use super::*;
use crate::AuditKeyPin;
use crate::ports::{
    AuditCreditSnapshot, AuditEventStore, AuditReadError, AuditReadRequest, AuditStoredPage, Clock,
    DocumentStore, EnvelopeCryptography, EnvelopeHeader, EventIntegrity, ExchangeStore, Identity,
    IntegrityError, KeyRegistry, SchemaArtifact, SchemaRegistry, SealedEnvelope,
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
    /// How many signatures the audit key has produced.
    signatures: AtomicUsize,
    /// How many upcoming replay lookups see the store as it was before a concurrent commit.
    stale_reads: AtomicUsize,
    /// The ledger the credit snapshot returns instead of one derived from the postings.
    ledger: Mutex<Option<Vec<CreditLedgerTransaction>>>,
    /// A failure the next credit snapshot returns.
    credit_snapshot_error: Mutex<Option<AuditReadError>>,
    /// The snapshot every audit page read was asked to continue, in order.
    page_snapshots: Mutex<Vec<Option<AuditSnapshot>>>,
    /// A failure the next page read that names a snapshot returns. A read selecting the
    /// current snapshot never consumes it.
    snapshot_read_error: Mutex<Option<AuditReadError>>,
    /// A page the next page read that names a snapshot returns instead of the stored rows,
    /// standing in for a store that answers two reads inconsistently.
    snapshot_read_page: Mutex<Option<AuditStoredPage>>,
    /// Audit-store calls of either operation.
    audit_reads: AtomicUsize,
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
            signatures: AtomicUsize::new(0),
            stale_reads: AtomicUsize::new(0),
            ledger: Mutex::new(None),
            credit_snapshot_error: Mutex::new(None),
            page_snapshots: Mutex::new(Vec::new()),
            snapshot_read_error: Mutex::new(None),
            snapshot_read_page: Mutex::new(None),
            audit_reads: AtomicUsize::new(0),
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

/// The fake audit key's deterministic signature over `input`.
fn fake_signature(input: &[u8]) -> [u8; 64] {
    let first = sha256(&[b"fake-audit-key".as_slice(), input].concat());
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&first);
    signature[32..].copy_from_slice(&sha256(&first));
    signature
}

impl EventIntegrity for Fake {
    fn public_key(&self) -> Result<[u8; 32], IntegrityError> {
        Ok([42; 32])
    }

    fn sign(&self, input: &[u8]) -> Result<[u8; 64], IntegrityError> {
        self.signatures.fetch_add(1, Ordering::SeqCst);
        Ok(fake_signature(input))
    }

    fn verify(&self, input: &[u8], signature: &[u8; 64]) -> Result<(), IntegrityError> {
        (fake_signature(input) == *signature)
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

impl AuditEventStore for Fake {
    async fn credit_snapshot(
        &self,
        max_transactions: u32,
    ) -> Result<AuditCreditSnapshot, AuditReadError> {
        self.audit_reads.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self
            .credit_snapshot_error
            .lock()
            .expect("credit snapshot error")
            .take()
        {
            return Err(error);
        }
        let events = self.events.lock().expect("events");
        let snapshot = AuditSnapshot::new(
            u64::try_from(events.len()).map_err(|_| AuditReadError::Invariant)?,
            events.last().map(AuditEvent::checkpoint),
        )
        .map_err(|_| AuditReadError::Invariant)?;
        let transactions = self
            .ledger
            .lock()
            .expect("ledger")
            .clone()
            .unwrap_or_else(|| {
                self.postings
                    .lock()
                    .expect("postings")
                    .iter()
                    .map(|posting| CreditLedgerTransaction {
                        eligibility_key: posting.eligibility_key.clone(),
                        exchange_id: posting
                            .eligibility_key
                            .strip_prefix("acceptance:")
                            .map(str::to_owned),
                        entries: vec![
                            CreditLedgerEntry {
                                account: ISSUANCE_ACCOUNT.to_owned(),
                                amount: -posting.amount,
                            },
                            CreditLedgerEntry {
                                account: posting.wallet.as_str().to_owned(),
                                amount: posting.amount,
                            },
                        ],
                    })
                    .collect()
            });
        if transactions.len() > usize::try_from(max_transactions).unwrap_or(usize::MAX) {
            return Err(AuditReadError::Exhausted);
        }
        Ok(AuditCreditSnapshot {
            snapshot,
            transactions,
        })
    }

    async fn page(&self, request: AuditReadRequest) -> Result<AuditStoredPage, AuditReadError> {
        self.audit_reads.fetch_add(1, Ordering::SeqCst);
        self.page_snapshots
            .lock()
            .expect("page snapshots")
            .push(request.snapshot);
        if request.snapshot.is_some() {
            if let Some(error) = self
                .snapshot_read_error
                .lock()
                .expect("snapshot read error")
                .take()
            {
                return Err(error);
            }
            if let Some(page) = self
                .snapshot_read_page
                .lock()
                .expect("snapshot read page")
                .take()
            {
                return Ok(page);
            }
        }
        let events = self.events.lock().expect("events");
        let selected = AuditSnapshot::new(
            u64::try_from(events.len()).map_err(|_| AuditReadError::Invariant)?,
            events.last().map(AuditEvent::checkpoint),
        )
        .map_err(|_| AuditReadError::Invariant)?;
        let snapshot = request.snapshot.unwrap_or(selected);
        if let Some(expected) = request.snapshot {
            let matches = expected.event_count() == 0
                || usize::try_from(expected.event_count())
                    .ok()
                    .and_then(|count| count.checked_sub(1))
                    .and_then(|index| events.get(index))
                    .map(AuditEvent::checkpoint)
                    == expected.head();
            if !matches {
                return Err(AuditReadError::SnapshotChanged);
            }
        }
        let start =
            usize::try_from(request.after_sequence).map_err(|_| AuditReadError::Invariant)?;
        let end = usize::try_from(snapshot.event_count()).map_err(|_| AuditReadError::Invariant)?;
        if start > end || end > events.len() {
            return Err(AuditReadError::SnapshotChanged);
        }
        if start > 0 && events.get(start - 1).is_none() {
            return Err(AuditReadError::SnapshotChanged);
        }
        let limit = usize::try_from(request.limit).map_err(|_| AuditReadError::Invariant)?;
        let page = events[start..end]
            .iter()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        Ok(AuditStoredPage {
            snapshot,
            has_more: start.saturating_add(page.len()) < end,
            events: page,
        })
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
    type AuditEvents = Fake;
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
    fn audit_events(&self) -> &Fake {
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
    let fake = Fake::new();
    let public_key = fake.public_key().expect("public key");
    let proof = AuditPublicKey::new(public_key, AuditKeyPin::new(sha256(&public_key)))
        .expect("matching pin");
    let audit = AuditSettings::new(proof, limits.audit_events, 100).expect("audit settings");
    Application::new(Fakes(fake), limits, audit)
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
    let fake_state = fake(&application);
    for caller in [actor(SENDER), actor(RECIPIENT), Actor::Operator] {
        assert_eq!(
            block_on(application.verify_audit(&caller, None)),
            Err(ApplicationError::Forbidden)
        );
    }
    // A refused caller causes no audit-store read at all.
    assert_eq!(fake_state.audit_reads.load(Ordering::SeqCst), 0);
    let report = block_on(application.verify_audit(&Actor::Auditor, None)).expect("verified");
    assert_eq!(report.event_count, 2);
    assert_eq!(
        (
            report.credits.accepted_exchanges(),
            report.credits.credit_transactions()
        ),
        (1, 1)
    );
    let head = report.head.expect("head");

    let removed = fake_state
        .events
        .lock()
        .expect("events")
        .pop()
        .expect("event");
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, Some(head))),
        Err(ApplicationError::AuditMismatch(AuditMismatch::EventChain))
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
        Err(ApplicationError::AuditMismatch(
            AuditMismatch::EnvelopeCommitment
        ))
    );
}

#[test]
fn audit_pages_continue_the_credit_snapshot_from_the_start() {
    let application = application_with(Limits {
        audit_events: 2_000,
        ..Limits::default()
    });
    let fake_state = fake(&application);
    block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    let record = fake_state.exchanges.lock().expect("exchanges")[0].clone();
    // Enough events for three pages of 500.
    for _ in 0..1_000 {
        fake_state
            .append(draft(&record, EventKind::Delivered), fake_state)
            .expect("event");
    }
    let report = block_on(application.verify_audit(&Actor::Auditor, None)).expect("verified");
    assert_eq!(report.event_count, 1_001);
    let tail = fake_state
        .events
        .lock()
        .expect("events")
        .last()
        .map(AuditEvent::checkpoint);
    let pages = fake_state.page_snapshots.lock().expect("pages").clone();
    assert_eq!(pages.len(), 3);
    assert!(pages.iter().all(|page| {
        page.is_some_and(|snapshot| snapshot.head() == tail && snapshot.event_count() == 1_001)
    }));
}

#[test]
fn audit_ledger_beyond_the_bound_is_incomplete() {
    let application = application();
    let fake_state = fake(&application);
    *fake_state
        .credit_snapshot_error
        .lock()
        .expect("credit snapshot error") = Some(AuditReadError::Exhausted);
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditIncomplete)
    );
    // The fake store applies the bound it is given, which is the verify event limit.
    let application = application_with(Limits {
        audit_events: 1,
        ..Limits::default()
    });
    let fake_state = fake(&application);
    let posting = |index: u8| CreditLedgerTransaction {
        eligibility_key: format!("acceptance:{index}"),
        exchange_id: None,
        entries: Vec::new(),
    };
    *fake_state.ledger.lock().expect("ledger") = Some(vec![posting(1), posting(2)]);
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditIncomplete)
    );
    for (error, expected) in [
        (
            AuditReadError::SnapshotChanged,
            ApplicationError::AuditMismatch(AuditMismatch::EventChain),
        ),
        (
            AuditReadError::Invariant,
            ApplicationError::AuditMismatch(AuditMismatch::EventChain),
        ),
        (AuditReadError::Transient, ApplicationError::Unavailable),
        (AuditReadError::Permanent, ApplicationError::Unavailable),
    ] {
        *fake_state
            .credit_snapshot_error
            .lock()
            .expect("credit snapshot error") = Some(error);
        assert_eq!(
            block_on(application.verify_audit(&Actor::Auditor, None)),
            Err(expected),
            "{error:?}"
        );
    }
}

#[test]
fn chain_and_envelope_failures_answer_before_credit_reconciliation() {
    let application = application();
    let fake_state = fake(&application);
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    block_on(application.accept(
        &actor(RECIPIENT),
        &delivery.exchange_id,
        &key("idem_accept0000000001"),
    ))
    .expect("acceptance");
    // The ledger is missing the credit throughout.
    *fake_state.ledger.lock().expect("ledger") = Some(Vec::new());
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditMismatch(
            AuditMismatch::CreditMissing
        ))
    );

    let original = fake_state.objects.lock().expect("objects")[&delivery.object_id].clone();
    fake_state
        .objects
        .lock()
        .expect("objects")
        .insert(delivery.object_id.clone(), b"substituted".to_vec());
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditMismatch(
            AuditMismatch::EnvelopeCommitment
        ))
    );
    fake_state
        .objects
        .lock()
        .expect("objects")
        .remove(&delivery.object_id);
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditMismatch(
            AuditMismatch::EnvelopeCommitment
        ))
    );

    fake_state.events.lock().expect("events")[0]
        .draft
        .registry_sequence += 1;
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditMismatch(AuditMismatch::EventChain))
    );
    fake_state.events.lock().expect("events")[0]
        .draft
        .registry_sequence -= 1;
    fake_state
        .objects
        .lock()
        .expect("objects")
        .insert(delivery.object_id, original);
    *fake_state.ledger.lock().expect("ledger") = None;
    assert!(block_on(application.verify_audit(&Actor::Auditor, None)).is_ok());
}

#[test]
fn a_repeated_signed_acceptance_is_an_event_chain_failure() {
    let application = application();
    let fake_state = fake(&application);
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    block_on(application.accept(
        &actor(RECIPIENT),
        &delivery.exchange_id,
        &key("idem_accept0000000001"),
    ))
    .expect("acceptance");
    let record = fake_state.exchanges.lock().expect("exchanges")[0].clone();
    fake_state
        .append(draft(&record, EventKind::Accepted), fake_state)
        .expect("second signed acceptance");
    assert_eq!(
        block_on(application.verify_audit(&Actor::Auditor, None)),
        Err(ApplicationError::AuditMismatch(AuditMismatch::EventChain))
    );
}

#[test]
fn each_credit_mismatch_reports_its_reason() {
    let application = application();
    let fake_state = fake(&application);
    let delivery = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    block_on(application.accept(
        &actor(RECIPIENT),
        &delivery.exchange_id,
        &key("idem_accept0000000001"),
    ))
    .expect("acceptance");
    let expected = CreditLedgerTransaction {
        eligibility_key: format!("acceptance:{}", delivery.exchange_id),
        exchange_id: Some(delivery.exchange_id.to_string()),
        entries: vec![
            CreditLedgerEntry {
                account: ISSUANCE_ACCOUNT.to_owned(),
                amount: -1,
            },
            CreditLedgerEntry {
                account: SENDER.to_owned(),
                amount: 1,
            },
        ],
    };
    let mut unaccepted = expected.clone();
    unaccepted.exchange_id = Some("exc_00000000000000000000000000000009".to_owned());
    let mut unbalanced = expected.clone();
    unbalanced.entries[1].account = RECIPIENT.to_owned();
    for (ledger, reason) in [
        (vec![expected.clone()], None),
        (
            vec![expected.clone(), unaccepted],
            Some(AuditMismatch::CreditUnaccepted),
        ),
        (
            vec![expected.clone(), expected.clone()],
            Some(AuditMismatch::CreditDuplicate),
        ),
        (vec![unbalanced], Some(AuditMismatch::CreditUnbalanced)),
        (vec![], Some(AuditMismatch::CreditMissing)),
    ] {
        *fake_state.ledger.lock().expect("ledger") = Some(ledger);
        let verified = block_on(application.verify_audit(&Actor::Auditor, None));
        match reason {
            None => assert!(verified.is_ok()),
            Some(reason) => assert_eq!(
                verified,
                Err(ApplicationError::AuditMismatch(reason)),
                "{}",
                reason.as_str()
            ),
        }
    }
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
fn publishes_only_the_pinned_audit_public_key_to_auditors() {
    let application = application();
    for caller in [actor(SENDER), Actor::Operator] {
        assert_eq!(
            application.audit_public_key(&caller),
            Err(ApplicationError::Forbidden)
        );
    }
    let proof = application
        .audit_public_key(&Actor::Auditor)
        .expect("auditor proof");
    assert_eq!(proof.public_key(), [42; 32]);
    assert_eq!(proof.fingerprint().as_bytes(), sha256(&[42; 32]));
    assert_eq!(format!("{proof:?}"), "AuditPublicKey(redacted)");
    assert!(AuditPublicKey::new([42; 32], AuditKeyPin::new([0; 32])).is_err());
}

/// Delivers and accepts one copy, leaving two events.
fn two_events(application: &Application<Fakes>) {
    let delivered = block_on(application.send_copy(&actor(SENDER), command())).expect("delivery");
    block_on(application.accept(
        &actor(RECIPIENT),
        &delivered.exchange_id,
        &key("idem_accept0000000001"),
    ))
    .expect("acceptance");
}

fn start(challenge: u8, limit: Option<u32>) -> AuditExportRequest {
    AuditExportRequest::start(AuditChallenge::new([challenge; 32]), limit).expect("bounded start")
}

fn next_page(
    application: &Application<Fakes>,
    page: &AuditExportPage,
    limit: Option<u32>,
) -> Result<AuditExportPage, ApplicationError> {
    block_on(
        application.export_audit_events(
            &Actor::Auditor,
            AuditExportRequest::continuation(
                page.manifest,
                page.manifest_signature,
                page.next_after_sequence.expect("partial page"),
                limit,
            )
            .expect("bounded continuation"),
        ),
    )
}

#[test]
fn exports_challenge_bound_snapshot_pages_only_to_auditors() {
    let application = application();
    let pin = sha256(&[42; 32]);

    // An empty chain is one complete page with a signed manifest and no head.
    let empty = block_on(application.export_audit_events(&Actor::Auditor, start(6, None)))
        .expect("empty export");
    assert_eq!(
        (
            empty.coverage,
            empty.events.len(),
            empty.next_after_sequence
        ),
        (Coverage::Complete, 0, None)
    );
    assert_eq!(empty.manifest.snapshot().head(), None);

    two_events(&application);
    for caller in [actor(SENDER), actor(RECIPIENT), Actor::Operator] {
        assert_eq!(
            block_on(application.export_audit_events(&caller, start(7, Some(1)))),
            Err(ApplicationError::Forbidden)
        );
    }
    let first = block_on(application.export_audit_events(&Actor::Auditor, start(7, Some(1))))
        .expect("first page");
    assert_eq!((first.coverage, first.events.len()), (Coverage::Partial, 1));
    assert_eq!(first.next_after_sequence, Some(1));
    assert_eq!(first.manifest.challenge(), AuditChallenge::new([7; 32]));
    assert_eq!(first.manifest.audit_key_fingerprint(), pin);
    assert_eq!(first.manifest.snapshot().event_count(), 2);
    assert!(
        fake(&application)
            .verify(
                &first.manifest.signature_input_v1(),
                &first.manifest_signature
            )
            .is_ok()
    );
    let stored = fake(&application).events.lock().expect("events").clone();
    let event = &first.events[0];
    assert_eq!(event.preimage_version, 1);
    assert_eq!(event.preimage, stored[0].preimage_v1().expect("preimage"));
    assert_eq!(sha256(&event.preimage), stored[0].event_hash);
    assert_eq!(
        (event.sequence, event.previous_event_hash, event.event_hash),
        (1, [0; 32], stored[0].event_hash)
    );
    assert_eq!(format!("{first:?}"), "AuditExportPage(redacted)");

    // An event appended between pages stays outside the selected snapshot.
    let mut later = command();
    later.idempotency_key = key("idem_0000000000000009");
    later.request_nonce = RequestNonce::new([9; 16]);
    later.document_version = DocumentVersion::new(2).expect("version");
    block_on(application.send_copy(&actor(SENDER), later)).expect("append");
    let second = next_page(&application, &first, Some(1)).expect("second page");
    assert_eq!(
        (
            second.coverage,
            second.events.len(),
            second.next_after_sequence
        ),
        (Coverage::Complete, 1, None)
    );
    assert_eq!(second.events[0].sequence, 2);
    assert_eq!(second.events[0].previous_event_hash, stored[0].event_hash);
    assert_eq!(second.manifest, first.manifest);
    assert_eq!(second.manifest_signature, first.manifest_signature);

    // Without a limit the configured default applies.
    let whole = block_on(application.export_audit_events(&Actor::Auditor, start(8, None)))
        .expect("default page size");
    assert_eq!(
        (whole.coverage, whole.events.len()),
        (Coverage::Complete, 3)
    );
}

#[test]
fn audit_export_fails_closed_on_manifest_pagination_and_total_bounds() {
    for limit in [0, 501] {
        assert_eq!(
            AuditExportRequest::start(AuditChallenge::new([1; 32]), Some(limit)),
            Err(ApplicationError::InvalidRequest)
        );
    }
    let application = application();
    two_events(&application);
    let first = block_on(application.export_audit_events(&Actor::Auditor, start(2, Some(1))))
        .expect("first page");
    for (after, limit) in [
        (0, None),
        (2, None),
        (3, None),
        (1, Some(0)),
        (1, Some(501)),
    ] {
        assert_eq!(
            AuditExportRequest::continuation(
                first.manifest,
                first.manifest_signature,
                after,
                limit
            ),
            Err(ApplicationError::InvalidRequest),
            "{after}/{limit:?}"
        );
    }

    // A manifest this key did not sign, or one naming another key, is refused before any read.
    let mut bad_signature = first.clone();
    bad_signature.manifest_signature[0] ^= 1;
    // Reusing a signed manifest under another challenge does not verify.
    let mut rechallenged = first.clone();
    rechallenged.manifest = AuditExportManifest::new(
        AuditChallenge::new([9; 32]),
        first.manifest.audit_key_fingerprint(),
        first.manifest.snapshot(),
    );
    let mut foreign = first.clone();
    foreign.manifest = AuditExportManifest::new(
        first.manifest.challenge(),
        [3; 32],
        first.manifest.snapshot(),
    );
    foreign.manifest_signature = fake(&application)
        .sign(&foreign.manifest.signature_input_v1())
        .expect("signature");
    for page in [&bad_signature, &rechallenged, &foreign] {
        assert_eq!(
            next_page(&application, page, Some(1)),
            Err(ApplicationError::InvalidRequest)
        );
    }

    // A snapshot whose head no longer holds fails closed rather than returning a prefix.
    let removed = fake(&application).events.lock().expect("events").pop();
    assert!(removed.is_some());
    assert_eq!(
        next_page(&application, &first, Some(1)),
        Err(ApplicationError::IntegrityFailure)
    );
    fake(&application)
        .events
        .lock()
        .expect("events")
        .extend(removed);

    // A stored event whose signature or link fails is never exported.
    let original = fake(&application).events.lock().expect("events")[0].clone();
    fake(&application).events.lock().expect("events")[0].signature[0] ^= 1;
    assert_eq!(
        block_on(application.export_audit_events(&Actor::Auditor, start(4, None))),
        Err(ApplicationError::IntegrityFailure)
    );
    fake(&application).events.lock().expect("events")[0] = original;
    fake(&application).events.lock().expect("events")[1].previous_hash[0] ^= 1;
    assert_eq!(
        block_on(application.export_audit_events(&Actor::Auditor, start(4, None))),
        Err(ApplicationError::IntegrityFailure)
    );

    // Beyond the configured total there is no page and no head, for a start or a continuation.
    let limited = application_with(Limits {
        audit_events: 1,
        ..Limits::default()
    });
    two_events(&limited);
    assert_eq!(
        block_on(limited.export_audit_events(&Actor::Auditor, start(3, None))),
        Err(ApplicationError::AuditIncomplete)
    );
    let unlimited = application_with(Limits::default());
    two_events(&unlimited);
    let signed = block_on(unlimited.export_audit_events(&Actor::Auditor, start(3, Some(1))))
        .expect("signed elsewhere");
    assert_eq!(
        next_page(&limited, &signed, Some(1)),
        Err(ApplicationError::AuditIncomplete)
    );
}

#[test]
fn audit_export_start_over_tampered_head_signature_fails_and_signs_nothing() {
    let application = application();
    two_events(&application);
    // With one event per page the first page never reaches the head, so only the start's own
    // check stands between a tampered head and a signed manifest naming it.
    fake(&application).events.lock().expect("events")[1].signature[0] ^= 1;
    let signed_before = fake(&application).signatures.load(Ordering::SeqCst);
    assert_eq!(
        block_on(application.export_audit_events(&Actor::Auditor, start(5, Some(1)))),
        Err(ApplicationError::IntegrityFailure)
    );
    assert_eq!(
        fake(&application).signatures.load(Ordering::SeqCst),
        signed_before
    );
}

#[test]
fn audit_export_partition_boundaries_cover_each_sequence_once() {
    for count in [0_u64, 1, 499, 500, 501, 100_000] {
        for limit in [1_u32, 100, 500] {
            let mut after = 0_u64;
            let mut covered = Vec::new();
            loop {
                let last = after.saturating_add(u64::from(limit)).min(count);
                let returned = usize::try_from(last - after).expect("bounded page length");
                let has_more = last < count;
                let (coverage, next) =
                    page_markers(count, last, returned, has_more, limit).expect("valid partition");
                covered.extend((after + 1)..=last);
                match (coverage, next) {
                    (Coverage::Partial, Some(cursor)) => after = cursor,
                    (Coverage::Complete, None) => break,
                    markers => panic!("invalid markers: {markers:?}"),
                }
            }
            assert_eq!(covered, (1..=count).collect::<Vec<_>>(), "{count}/{limit}");
        }
    }
    assert_eq!(
        page_markers(2, 1, 0, true, 1),
        Err(ApplicationError::IntegrityFailure)
    );
    assert_eq!(
        page_markers(2, 1, 1, false, 1),
        Err(ApplicationError::IntegrityFailure)
    );
}

/// An application whose chain holds `count` events appended straight into the fake store, each
/// recording the same valid draft.
fn seeded(count: usize) -> Application<Fakes> {
    let source = application();
    block_on(source.send_copy(&actor(SENDER), command())).expect("delivery");
    let draft = fake(&source).events.lock().expect("events")[0]
        .draft
        .clone();
    let application = application();
    let state = fake(&application);
    for _ in 0..count {
        state.append(draft.clone(), state).expect("append");
    }
    application
}

/// The snapshot the fake's current chain names.
fn current_snapshot(state: &Fake) -> AuditSnapshot {
    let events = state.events.lock().expect("events");
    AuditSnapshot::new(
        u64::try_from(events.len()).expect("small chain"),
        events.last().map(AuditEvent::checkpoint),
    )
    .expect("valid snapshot")
}

fn start_export(
    application: &Application<Fakes>,
    limit: u32,
) -> Result<AuditExportPage, ApplicationError> {
    block_on(application.export_audit_events(&Actor::Auditor, start(5, Some(limit))))
}

#[test]
fn audit_export_start_over_misplaced_signed_head_fails_and_signs_nothing() {
    // With one event per page only the start's own head check sees the head row; with 500 the
    // first page holds it, and its checks must still run before the manifest is signed.
    for limit in [1, 500] {
        let application = seeded(2);
        let state = fake(&application);
        {
            let mut events = state.events.lock().expect("events");
            // The head row carries event 1's hash and that hash's valid signature, so the head
            // signature verifies but the hash does not belong to sequence 2.
            events[1].event_hash = events[0].event_hash;
            events[1].signature = events[0].signature;
        }
        let signed_before = state.signatures.load(Ordering::SeqCst);
        assert_eq!(
            start_export(&application, limit),
            Err(ApplicationError::IntegrityFailure),
            "{limit}"
        );
        assert_eq!(
            state.signatures.load(Ordering::SeqCst),
            signed_before,
            "{limit}"
        );
    }
}

#[test]
fn audit_export_start_signs_one_manifest_for_untampered_chains() {
    for count in [0_usize, 1, 2] {
        for limit in [1_u32, 500] {
            let application = seeded(count);
            let state = fake(&application);
            let selected = current_snapshot(state);
            let signed_before = state.signatures.load(Ordering::SeqCst);
            let page = start_export(&application, limit).expect("start page");
            assert_eq!(
                state.signatures.load(Ordering::SeqCst),
                signed_before + 1,
                "{count}/{limit}"
            );
            assert_eq!(page.manifest.snapshot(), selected, "{count}/{limit}");
            assert!(
                state
                    .verify(
                        &page.manifest.signature_input_v1(),
                        &page.manifest_signature
                    )
                    .is_ok()
            );
            let returned = count.min(usize::try_from(limit).expect("small limit"));
            let last = u64::try_from(returned).expect("small page");
            assert_eq!(
                page.events
                    .iter()
                    .map(|event| event.sequence)
                    .collect::<Vec<_>>(),
                (1..=last).collect::<Vec<_>>(),
                "{count}/{limit}"
            );
            let stops_before_head = returned < count;
            let (coverage, cursor, reads) = if stops_before_head {
                (Coverage::Partial, Some(last), vec![None, Some(selected)])
            } else {
                (Coverage::Complete, None, vec![None])
            };
            assert_eq!(
                (page.coverage, page.next_after_sequence),
                (coverage, cursor),
                "{count}/{limit}"
            );
            assert_eq!(
                *state.page_snapshots.lock().expect("pages"),
                reads,
                "{count}/{limit}"
            );
        }
    }
}

#[test]
fn audit_export_start_fails_closed_when_the_head_read_fails_and_signs_nothing() {
    for (error, expected) in [
        (AuditReadError::Transient, ApplicationError::Unavailable),
        (AuditReadError::Permanent, ApplicationError::Unavailable),
        (
            AuditReadError::SnapshotChanged,
            ApplicationError::IntegrityFailure,
        ),
        (
            AuditReadError::Invariant,
            ApplicationError::IntegrityFailure,
        ),
    ] {
        let application = seeded(2);
        let state = fake(&application);
        let selected = current_snapshot(state);
        // Queued for the snapshot-naming read only, so the first read cannot absorb it.
        *state
            .snapshot_read_error
            .lock()
            .expect("snapshot read error") = Some(error);
        let signed_before = state.signatures.load(Ordering::SeqCst);
        assert_eq!(start_export(&application, 1), Err(expected), "{error:?}");
        assert_eq!(
            state.signatures.load(Ordering::SeqCst),
            signed_before,
            "{error:?}"
        );
        assert_eq!(
            *state.page_snapshots.lock().expect("pages"),
            vec![None, Some(selected)],
            "{error:?}"
        );
        assert!(
            state
                .snapshot_read_error
                .lock()
                .expect("snapshot read error")
                .is_none(),
            "the head read returned the queued failure"
        );
    }
}

#[test]
fn audit_export_start_refuses_a_head_read_other_than_the_signed_head_and_signs_nothing() {
    let application = seeded(2);
    let state = fake(&application);
    let stored = state.events.lock().expect("events").clone();
    let selected = current_snapshot(state);
    let earlier = AuditSnapshot::new(1, Some(stored[0].checkpoint())).expect("snapshot");
    // Another event, validly hashed and signed at the head's own sequence and link.
    let mut draft = stored[1].draft.clone();
    draft.document_version = DocumentVersion::new(9).expect("version");
    let hash = AuditEvent::hash_for(&draft, 2, &stored[0].event_hash).expect("hash");
    let rival = AuditEvent::assemble(
        draft,
        2,
        stored[0].event_hash,
        fake_signature(&event_signature_input(&hash)),
    )
    .expect("rival event");
    assert!(AuditExportEvent::from_stored(rival.clone()).is_ok());
    let answer = |snapshot, events, has_more| AuditStoredPage {
        snapshot,
        events,
        has_more,
    };
    let head = || stored[1].clone();
    let first = || stored[0].clone();
    for (case, page) in [
        (
            "another valid event at the head's sequence",
            answer(selected, vec![rival], false),
        ),
        (
            "a valid event at another sequence",
            answer(selected, vec![first()], false),
        ),
        ("no event", answer(selected, vec![], false)),
        (
            "the head, then another event",
            answer(selected, vec![head(), first()], false),
        ),
        (
            "another event, then the head",
            answer(selected, vec![first(), head()], false),
        ),
        (
            "the head, claiming more events",
            answer(selected, vec![head()], true),
        ),
        (
            "the head, under another snapshot",
            answer(earlier, vec![head()], false),
        ),
    ] {
        state.page_snapshots.lock().expect("pages").clear();
        *state.snapshot_read_page.lock().expect("snapshot read page") = Some(page);
        let signed_before = state.signatures.load(Ordering::SeqCst);
        assert_eq!(
            start_export(&application, 1),
            Err(ApplicationError::IntegrityFailure),
            "{case}"
        );
        assert_eq!(
            state.signatures.load(Ordering::SeqCst),
            signed_before,
            "{case}"
        );
        assert_eq!(
            *state.page_snapshots.lock().expect("pages"),
            vec![None, Some(selected)],
            "{case}"
        );
    }

    // The same queued answer holding exactly the signed head is accepted, so each refusal
    // above comes from its own defect.
    *state.snapshot_read_page.lock().expect("snapshot read page") =
        Some(answer(selected, vec![head()], false));
    let signed_before = state.signatures.load(Ordering::SeqCst);
    assert!(start_export(&application, 1).is_ok());
    assert_eq!(state.signatures.load(Ordering::SeqCst), signed_before + 1);
}

#[test]
fn audit_export_use_case_pages_cover_each_sequence_once() {
    for count in [0_usize, 1, 499, 500, 501] {
        let application = seeded(count);
        let state = fake(&application);
        let total = u64::try_from(count).expect("small chain");
        for limit in [1_u32, 100, 500] {
            let signed_before = state.signatures.load(Ordering::SeqCst);
            let mut page = start_export(&application, limit).expect("start page");
            let (manifest, signature) = (page.manifest, page.manifest_signature);
            let mut covered = Vec::new();
            let mut pages = 1_usize;
            loop {
                assert_eq!(
                    (page.manifest, page.manifest_signature),
                    (manifest, signature),
                    "{count}/{limit}"
                );
                covered.extend(page.events.iter().map(|event| event.sequence));
                match (page.coverage, page.next_after_sequence) {
                    (Coverage::Partial, Some(cursor)) => {
                        assert_eq!(
                            page.events.last().map(|event| event.sequence),
                            Some(cursor),
                            "{count}/{limit}"
                        );
                        page = next_page(&application, &page, Some(limit)).expect("next page");
                        pages += 1;
                    }
                    (Coverage::Complete, None) => break,
                    markers => panic!("invalid markers at {count}/{limit}: {markers:?}"),
                }
            }
            assert_eq!(covered, (1..=total).collect::<Vec<_>>(), "{count}/{limit}");
            assert_eq!(
                pages,
                count
                    .div_ceil(usize::try_from(limit).expect("small limit"))
                    .max(1),
                "{count}/{limit}"
            );
            assert_eq!(
                state.signatures.load(Ordering::SeqCst),
                signed_before + 1,
                "{count}/{limit}"
            );
        }
    }
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
