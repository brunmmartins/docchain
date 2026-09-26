//! The use cases: send copy, accept, read, list, and audit.
//!
//! Every use case authorizes the actor before any document-store read or decryption, and every
//! mutation commits through one store transaction guarded by uniqueness rules, so a replay or a
//! cancelled call cannot produce a second event, envelope, delivery, acceptance, or credit.

use std::fmt::Write as _;

use docchain_domain::{
    CompiledSchema, EventDraft, EventKind, ExchangeId, IdempotencyKey, ObjectId, WalletId,
    envelope_commitment, parse_document, sha256, verify_event_chain,
};

use crate::{
    AcceptanceResult, Actor, ApplicationError, AuditReport, Credential, Delivery, Limits,
    Plaintext, SendCopyCommand,
    ports::{
        AcceptanceOutcome, Adapters, Clock as _, CreditPosting, CryptoError, DocumentStore as _,
        EnvelopeCryptography as _, EventIntegrity as _, ExchangeRecord, ExchangeStore as _,
        HeaderKey, Identity as _, IdentityError, KeyPurpose, KeyRegistry as _, KeyRegistryError,
        OpenRequest, SchemaRegistry as _, SchemaRegistryError, SealRequest, StoreError,
        VerifiedBinding,
    },
};

const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// The application: use cases over statically dispatched adapters.
pub struct Application<A: Adapters> {
    adapters: A,
    limits: Limits,
}

struct ActiveSchema {
    compiled: CompiledSchema,
    digest: [u8; 32],
}

impl<A: Adapters> Application<A> {
    /// Builds the application over its adapters.
    #[must_use]
    pub const fn new(adapters: A, limits: Limits) -> Self {
        Self { adapters, limits }
    }

    /// The adapters, for readiness checks and tests.
    #[must_use]
    pub const fn adapters(&self) -> &A {
        &self.adapters
    }

    /// Resolves a presented credential to an actor.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Unauthenticated`] for an unknown or inactive credential.
    pub async fn authenticate(&self, credential: &Credential) -> Result<Actor, ApplicationError> {
        self.adapters
            .identity()
            .authenticate(credential)
            .await
            .map_err(|error| match error {
                IdentityError::Unauthorized | IdentityError::Inactive => {
                    ApplicationError::Unauthenticated
                }
                IdentityError::Transient | IdentityError::Permanent => {
                    ApplicationError::Unavailable
                }
            })
    }

    /// Reports whether PostgreSQL is reachable and the document root is writable.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Unavailable`] when they are not.
    pub async fn ready(&self) -> Result<(), ApplicationError> {
        self.adapters
            .exchanges()
            .ping()
            .await
            .map_err(store_error)?;
        self.adapters
            .documents()
            .probe_writable()
            .await
            .map_err(store_error)
    }

    /// Validates, signs, encrypts, stores, and commits one copy for the recipient.
    ///
    /// A repeated request with the sender's idempotency key returns the prior delivery only
    /// when every field and the document match; anything else is a replay.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] unless the actor is the sending wallet;
    /// [`ApplicationError::UnsupportedSchema`] or [`ApplicationError::InvalidDocument`] before
    /// anything is stored; [`ApplicationError::Replay`] for a reused key, nonce, or document
    /// version; [`ApplicationError::PendingLimit`]; [`ApplicationError::KeyBinding`];
    /// [`ApplicationError::Unavailable`] when randomness or a store fails.
    pub async fn send_copy(
        &self,
        actor: &Actor,
        command: SendCopyCommand,
    ) -> Result<Delivery, ApplicationError> {
        let Actor::Wallet(wallet) = actor else {
            return Err(ApplicationError::Forbidden);
        };
        if *wallet != command.sender {
            return Err(ApplicationError::Forbidden);
        }
        if command.sender == command.recipient {
            return Err(ApplicationError::InvalidRequest);
        }
        let schema = self
            .active_schema(&command.schema_id, &command.schema_version)
            .await?;
        let document = parse_document(&command.document)?;
        schema.compiled.validate(document.value())?;

        let exchanges = self.adapters.exchanges();
        if let Some(prior) = exchanges
            .find_by_idempotency(&command.sender, &command.idempotency_key)
            .await
            .map_err(store_error)?
        {
            return self.replayed_send(&prior, &command, document.bytes()).await;
        }
        if exchanges
            .replay_exists(
                &command.sender,
                &command.request_nonce,
                &command.document_id,
                command.document_version,
                &command.recipient,
            )
            .await
            .map_err(store_error)?
        {
            // An identical request may have committed between the two reads; its sender then
            // gets that prior result rather than a replay error.
            return match exchanges
                .find_by_idempotency(&command.sender, &command.idempotency_key)
                .await
                .map_err(store_error)?
            {
                Some(prior) => self.replayed_send(&prior, &command, document.bytes()).await,
                None => Err(ApplicationError::Replay),
            };
        }

        let keys = self.adapters.keys();
        // Read once: every key check uses it, and the exchange and its events store it, so reads
        // later judge the keys as they stood at this instant.
        let now = self.adapters.clock().now();
        let signing = keys
            .resolve_active(&command.sender, KeyPurpose::DocumentSigning, now)
            .await
            .map_err(binding_error)?;
        let sender_encryption = keys
            .resolve_active(&command.sender, KeyPurpose::DocumentEncryption, now)
            .await
            .map_err(binding_error)?;
        let recipient_encryption = keys
            .resolve_active(&command.recipient, KeyPurpose::DocumentEncryption, now)
            .await
            .map_err(binding_error)?;
        let registry_sequence = keys.head_sequence().await.map_err(binding_error)?;

        let sealed = self
            .adapters
            .crypto()
            .seal(&SealRequest {
                canonical_document: document.bytes(),
                document_id: &command.document_id,
                document_version: command.document_version,
                request_nonce: &command.request_nonce,
                schema_id: &command.schema_id,
                schema_digest: schema.digest,
                sender_signing: &signing,
                recipients: [&sender_encryption, &recipient_encryption],
            })
            .map_err(|error| match error {
                CryptoError::EntropyExhausted => ApplicationError::Unavailable,
                CryptoError::InvalidKey => ApplicationError::KeyBinding,
                CryptoError::InvalidInput
                | CryptoError::UnsupportedSuite
                | CryptoError::AuthenticationFailed
                | CryptoError::Permanent => ApplicationError::Invariant,
            })?;
        drop(document);

        let record = ExchangeRecord {
            exchange_id: exchange_id(&command.sender, &command.idempotency_key)?,
            object_id: object_id(&sealed.commitment)?,
            sender: command.sender.clone(),
            recipient: command.recipient.clone(),
            document_id: command.document_id.clone(),
            document_version: command.document_version,
            request_nonce: command.request_nonce,
            idempotency_key: command.idempotency_key.clone(),
            schema_id: command.schema_id.clone(),
            schema_version: command.schema_version.clone(),
            envelope_commitment: sealed.commitment,
            protected_hash: sealed.protected_hash,
            envelope_version: sealed.envelope_version,
            registry_sequence,
            committed_at: now,
            accepted: false,
        };
        self.adapters
            .documents()
            .put_new(&record.object_id, &sealed.bytes)
            .await
            .map_err(store_error)?;

        let committed = exchanges
            .commit_send(
                &record,
                draft(&record, EventKind::Delivered),
                self.adapters.integrity(),
                self.limits.pending_per_relationship,
            )
            .await;
        match committed {
            Ok(()) => Ok(delivery(&record)),
            Err(error) => {
                self.discard_unreferenced(&record.object_id).await;
                match error {
                    StoreError::Conflict => {
                        let document = parse_document(&command.document)?;
                        match exchanges
                            .find_by_idempotency(&command.sender, &command.idempotency_key)
                            .await
                            .map_err(store_error)?
                        {
                            Some(prior) => {
                                self.replayed_send(&prior, &command, document.bytes()).await
                            }
                            None => Err(ApplicationError::Replay),
                        }
                    }
                    StoreError::PendingLimit => Err(ApplicationError::PendingLimit),
                    other => Err(store_error(other)),
                }
            }
        }
    }

    /// Records the recipient's acceptance and posts exactly one demonstration credit to the
    /// sender. Accepting an accepted exchange returns the prior result and writes nothing.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] unless the actor is the recipient of an existing
    /// exchange; [`ApplicationError::Replay`] when the recipient's idempotency key belongs to
    /// another acceptance; [`ApplicationError::Unavailable`] when the store fails.
    pub async fn accept(
        &self,
        actor: &Actor,
        exchange_id: &ExchangeId,
        key: &IdempotencyKey,
    ) -> Result<AcceptanceResult, ApplicationError> {
        let Actor::Wallet(wallet) = actor else {
            return Err(ApplicationError::Forbidden);
        };
        let exchanges = self.adapters.exchanges();
        let record = exchanges
            .find(exchange_id)
            .await
            .map_err(store_error)?
            .filter(|record| record.recipient == *wallet)
            .ok_or(ApplicationError::Forbidden)?;
        if !record.accepted {
            let credit = CreditPosting {
                eligibility_key: format!("acceptance:{}", record.exchange_id),
                wallet: record.sender.clone(),
                amount: 1,
            };
            exchanges
                .commit_acceptance(
                    &record.exchange_id,
                    key,
                    &credit,
                    draft(&record, EventKind::Accepted),
                    self.adapters.integrity(),
                )
                .await
                .map_err(|error| match error {
                    StoreError::Conflict => ApplicationError::Replay,
                    other => store_error(other),
                })
                .map(|_: AcceptanceOutcome| ())?;
        }
        Ok(AcceptanceResult {
            exchange_id: record.exchange_id,
            credit_awarded: 1,
        })
    }

    /// Returns the verified plaintext to a participant.
    ///
    /// Authorization precedes the document-store read and decryption, and an unknown exchange
    /// is indistinguishable from a forbidden one.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] for anyone but the sender or recipient;
    /// [`ApplicationError::InvalidEnvelope`] when any envelope, binding, signature, or schema
    /// check fails.
    pub async fn read_document(
        &self,
        actor: &Actor,
        exchange_id: &ExchangeId,
    ) -> Result<Plaintext, ApplicationError> {
        let Actor::Wallet(wallet) = actor else {
            return Err(ApplicationError::Forbidden);
        };
        let record = self
            .adapters
            .exchanges()
            .find(exchange_id)
            .await
            .map_err(store_error)?
            .filter(|record| record.sender == *wallet || record.recipient == *wallet)
            .ok_or(ApplicationError::Forbidden)?;
        self.open_record(&record, wallet).await
    }

    /// Lists pending exchanges addressed to the actor's own wallet.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] for any other wallet or role.
    pub async fn list_inbox(
        &self,
        actor: &Actor,
        wallet: &WalletId,
    ) -> Result<Vec<ExchangeId>, ApplicationError> {
        if *actor != Actor::Wallet(wallet.clone()) {
            return Err(ApplicationError::Forbidden);
        }
        self.adapters
            .exchanges()
            .pending_inbox(wallet, self.limits.inbox_page)
            .await
            .map_err(store_error)
    }

    /// Verifies the signed event chain and every envelope commitment, without plaintext.
    ///
    /// With `expected`, the chain must still contain that earlier head, so removing events
    /// after it is detected.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] unless the actor is an auditor;
    /// [`ApplicationError::IntegrityFailure`] on any failed check.
    pub async fn verify_audit(
        &self,
        actor: &Actor,
        expected: Option<docchain_domain::Checkpoint>,
    ) -> Result<AuditReport, ApplicationError> {
        if *actor != Actor::Auditor {
            return Err(ApplicationError::Forbidden);
        }
        let fetch_limit = self
            .limits
            .audit_events
            .checked_add(1)
            .ok_or(ApplicationError::Invariant)?;
        let events = self
            .adapters
            .exchanges()
            .events(fetch_limit)
            .await
            .map_err(|error| match error {
                StoreError::Invariant => ApplicationError::IntegrityFailure,
                other => store_error(other),
            })?;
        if events.len() > self.limits.audit_events as usize {
            return Err(ApplicationError::AuditIncomplete);
        }
        let integrity = self.adapters.integrity();
        let head = verify_event_chain(&events, expected.as_ref(), |input, signature| {
            integrity.verify(input, signature).is_ok()
        })
        .map_err(|_| ApplicationError::IntegrityFailure)?;
        for event in &events {
            let envelope = self
                .adapters
                .documents()
                .get(&event.draft.object_id)
                .await
                .map_err(|error| match error {
                    StoreError::NotFound => ApplicationError::IntegrityFailure,
                    other => store_error(other),
                })?;
            if envelope_commitment(&envelope) != event.draft.envelope_commitment {
                return Err(ApplicationError::IntegrityFailure);
            }
            let header = self
                .adapters
                .crypto()
                .inspect(&envelope)
                .map_err(|_| ApplicationError::IntegrityFailure)?;
            if header.protected_hash != event.draft.protected_hash
                || header.envelope_version != event.draft.envelope_version
                || header.document_id != event.draft.document_id
                || header.document_version != event.draft.document_version
                || header.sender.wallet != event.draft.sender
                || !names_exactly(
                    &header.recipients,
                    &event.draft.sender,
                    &event.draft.recipient,
                )
            {
                return Err(ApplicationError::IntegrityFailure);
            }
        }
        Ok(AuditReport {
            event_count: events.len(),
            head,
        })
    }

    async fn active_schema(
        &self,
        schema_id: &str,
        version: &str,
    ) -> Result<ActiveSchema, ApplicationError> {
        let artifact = self
            .adapters
            .schemas()
            .load_active(schema_id, version)
            .await
            .map_err(|error| match error {
                SchemaRegistryError::NotFound | SchemaRegistryError::Inactive => {
                    ApplicationError::UnsupportedSchema
                }
                SchemaRegistryError::Transient | SchemaRegistryError::Permanent => {
                    ApplicationError::Unavailable
                }
            })?;
        if artifact.id != schema_id || artifact.version != version {
            return Err(ApplicationError::UnsupportedSchema);
        }
        let parsed = docchain_domain::parse_bounded_json(
            &artifact.bytes,
            MAX_SCHEMA_BYTES,
            MAX_SCHEMA_DEPTH,
        )
        .map_err(|_| ApplicationError::UnsupportedSchema)?;
        let digest = sha256(parsed.bytes());
        if digest != artifact.approved_digest {
            return Err(ApplicationError::UnsupportedSchema);
        }
        let compiled = CompiledSchema::compile(parsed.value())
            .map_err(|_| ApplicationError::UnsupportedSchema)?;
        if compiled.id() != schema_id {
            return Err(ApplicationError::UnsupportedSchema);
        }
        Ok(ActiveSchema { compiled, digest })
    }

    async fn replayed_send(
        &self,
        prior: &ExchangeRecord,
        command: &SendCopyCommand,
        canonical_document: &[u8],
    ) -> Result<Delivery, ApplicationError> {
        if prior.sender != command.sender
            || prior.recipient != command.recipient
            || prior.document_id != command.document_id
            || prior.document_version != command.document_version
            || prior.request_nonce != command.request_nonce
            || prior.schema_id != command.schema_id
            || prior.schema_version != command.schema_version
        {
            return Err(ApplicationError::Replay);
        }
        // No plaintext digest is stored, so the sender's own copy is the comparison basis.
        let prior_document = self.open_record(prior, &command.sender).await?;
        if prior_document.as_bytes() != canonical_document {
            return Err(ApplicationError::Replay);
        }
        Ok(delivery(prior))
    }

    async fn open_record(
        &self,
        record: &ExchangeRecord,
        reader: &WalletId,
    ) -> Result<Plaintext, ApplicationError> {
        let envelope = self
            .adapters
            .documents()
            .get(&record.object_id)
            .await
            .map_err(|error| match error {
                StoreError::NotFound => ApplicationError::InvalidEnvelope,
                other => store_error(other),
            })?;
        if envelope_commitment(&envelope) != record.envelope_commitment {
            return Err(ApplicationError::InvalidEnvelope);
        }
        let crypto = self.adapters.crypto();
        let header = crypto
            .inspect(&envelope)
            .map_err(|_| ApplicationError::InvalidEnvelope)?;
        if header.protected_hash != record.protected_hash
            || header.envelope_version != record.envelope_version
            || header.document_id != record.document_id
            || header.document_version != record.document_version
            || header.schema_id != record.schema_id
            || header.sender.wallet != record.sender
            || !names_exactly(&header.recipients, &record.sender, &record.recipient)
        {
            return Err(ApplicationError::InvalidEnvelope);
        }
        let sender_signing = self
            .historic_binding(&header.sender, KeyPurpose::DocumentSigning, record)
            .await?;
        let reader_key = header
            .recipients
            .iter()
            .find(|key| key.wallet == *reader)
            .ok_or(ApplicationError::Forbidden)?;
        let reader_binding = self
            .historic_binding(reader_key, KeyPurpose::DocumentEncryption, record)
            .await?;
        let plaintext = crypto
            .open(
                &envelope,
                &OpenRequest {
                    header: &header,
                    reader: &reader_binding,
                    sender_signing: &sender_signing,
                },
            )
            .map_err(|_| ApplicationError::InvalidEnvelope)?;

        let document =
            parse_document(plaintext.as_bytes()).map_err(|_| ApplicationError::InvalidEnvelope)?;
        if document.bytes() != plaintext.as_bytes() {
            return Err(ApplicationError::InvalidEnvelope);
        }
        let schema = self
            .active_schema(&record.schema_id, &record.schema_version)
            .await
            .map_err(|error| match error {
                ApplicationError::Unavailable => ApplicationError::Unavailable,
                _ => ApplicationError::InvalidEnvelope,
            })?;
        if schema.digest != header.schema_digest {
            return Err(ApplicationError::InvalidEnvelope);
        }
        schema
            .compiled
            .validate(document.value())
            .map_err(|_| ApplicationError::InvalidEnvelope)?;
        Ok(plaintext)
    }

    /// Loads the binding a header pins and checks that it was the key's record in force when the
    /// send checked its keys: at the exchange's registry sequence and commit time.
    ///
    /// A record appended after the send, even one dated earlier, is beyond that sequence and
    /// cannot change the result; a revocation that takes effect later leaves the copy readable.
    async fn historic_binding(
        &self,
        key: &HeaderKey,
        purpose: KeyPurpose,
        record: &ExchangeRecord,
    ) -> Result<VerifiedBinding, ApplicationError> {
        let keys = self.adapters.keys();
        let invalid = |error: KeyRegistryError| match error {
            KeyRegistryError::Transient => ApplicationError::Unavailable,
            _ => ApplicationError::InvalidEnvelope,
        };
        let binding = keys.load(&key.binding_digest).await.map_err(invalid)?;
        if binding.wallet != key.wallet
            || binding.key_id != key.key_id
            || binding.purpose != purpose
        {
            return Err(ApplicationError::InvalidEnvelope);
        }
        let in_force = keys
            .effective_as_of(
                &binding.key_id,
                record.registry_sequence,
                record.committed_at,
            )
            .await
            .map_err(invalid)?;
        if in_force.binding_digest != key.binding_digest {
            return Err(ApplicationError::InvalidEnvelope);
        }
        Ok(binding)
    }

    /// Removes a just-written object only when no exchange references it. If that cannot be
    /// established, the object stays: an orphan is safer than a committed event pointing at a
    /// missing envelope.
    async fn discard_unreferenced(&self, object_id: &ObjectId) {
        if let Ok(false) = self.adapters.exchanges().object_referenced(object_id).await {
            let _ = self.adapters.documents().remove(object_id).await;
        }
    }
}

fn names_exactly(recipients: &[HeaderKey], sender: &WalletId, recipient: &WalletId) -> bool {
    recipients.len() == 2
        && recipients.iter().any(|key| key.wallet == *sender)
        && recipients.iter().any(|key| key.wallet == *recipient)
}

fn draft(record: &ExchangeRecord, kind: EventKind) -> EventDraft {
    EventDraft {
        kind,
        exchange_id: record.exchange_id.clone(),
        object_id: record.object_id.clone(),
        envelope_commitment: record.envelope_commitment,
        envelope_version: record.envelope_version,
        protected_hash: record.protected_hash,
        sender: record.sender.clone(),
        recipient: record.recipient.clone(),
        document_id: record.document_id.clone(),
        document_version: record.document_version,
        registry_sequence: record.registry_sequence,
        committed_at: record.committed_at,
    }
}

fn delivery(record: &ExchangeRecord) -> Delivery {
    Delivery {
        exchange_id: record.exchange_id.clone(),
        object_id: record.object_id.clone(),
        envelope_commitment: record.envelope_commitment,
    }
}

/// The exchange ID is derived from the sender and its idempotency key, so two concurrent
/// identical requests collide on the primary key instead of both committing.
fn exchange_id(sender: &WalletId, key: &IdempotencyKey) -> Result<ExchangeId, ApplicationError> {
    let digest = sha256(
        &[
            b"docchain/exchange-id/v1\0".as_slice(),
            sender.as_str().as_bytes(),
            b"\0",
            key.as_str().as_bytes(),
        ]
        .concat(),
    );
    ExchangeId::new(hex_id("exc_", &digest)).map_err(|_| ApplicationError::Invariant)
}

fn object_id(commitment: &[u8; 32]) -> Result<ObjectId, ApplicationError> {
    let digest = sha256(&[b"docchain/object-id/v1\0".as_slice(), commitment].concat());
    ObjectId::new(hex_id("obj_", &digest)).map_err(|_| ApplicationError::Invariant)
}

fn hex_id(prefix: &str, digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(prefix.len() + 32);
    output.push_str(prefix);
    for byte in &digest[..16] {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn store_error(error: StoreError) -> ApplicationError {
    match error {
        StoreError::Conflict => ApplicationError::Replay,
        StoreError::PendingLimit => ApplicationError::PendingLimit,
        StoreError::NotFound | StoreError::Invariant => ApplicationError::Invariant,
        StoreError::Transient | StoreError::Permanent => ApplicationError::Unavailable,
    }
}

fn binding_error(error: KeyRegistryError) -> ApplicationError {
    match error {
        KeyRegistryError::Transient | KeyRegistryError::Permanent => ApplicationError::Unavailable,
        KeyRegistryError::NotFound
        | KeyRegistryError::InvalidBinding
        | KeyRegistryError::Inactive
        | KeyRegistryError::Revoked
        | KeyRegistryError::Expired
        | KeyRegistryError::WrongPurpose => ApplicationError::KeyBinding,
    }
}

#[cfg(test)]
mod tests;
