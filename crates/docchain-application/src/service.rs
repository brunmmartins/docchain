//! The use cases: send copy, accept, read, list, and audit.
//!
//! Every use case authorizes the actor before any document-store read or decryption, and every
//! mutation commits through one store transaction guarded by uniqueness rules, so a replay or a
//! cancelled call cannot produce a second event, envelope, delivery, acceptance, or credit.

use std::{collections::BTreeMap, fmt::Write as _};

use docchain_domain::{
    AuditEvent, AuditExportManifest, AuditSnapshot, Checkpoint, CompiledSchema, EventDraft,
    EventKind, ExchangeId, IdempotencyKey, ObjectId, WalletId, acceptance_eligibility_key,
    envelope_commitment, event_signature_input, parse_document, reconcile_credits, sha256,
    verify_event_chain,
};

use crate::{
    AcceptanceResult, Actor, ApplicationError, AuditExportEvent, AuditExportPage,
    AuditExportRequest, AuditMismatch, AuditPublicKey, AuditReport, AuditSettings, Coverage,
    Credential, Delivery, Limits, Plaintext, SendCopyCommand,
    model::AuditExportKind,
    ports::{
        AcceptanceOutcome, Adapters, AuditEventStore as _, AuditReadError, AuditReadRequest,
        AuditStoredPage, Clock as _, CreditPosting, CryptoError, DocumentStore as _,
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
    audit: AuditSettings,
}

struct ActiveSchema {
    compiled: CompiledSchema,
    digest: [u8; 32],
}

impl<A: Adapters> Application<A> {
    /// Builds the application over its adapters.
    #[must_use]
    pub const fn new(adapters: A, limits: Limits, audit: AuditSettings) -> Self {
        Self {
            adapters,
            limits,
            audit,
        }
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
                eligibility_key: acceptance_eligibility_key(&record.exchange_id),
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

    /// Verifies the signed event chain, every envelope commitment, and the credit ledger,
    /// without plaintext.
    ///
    /// The chain tail and the whole credit ledger are read together in one snapshot, and the
    /// event pages are then read against that tail, so a concurrent acceptance cannot produce a
    /// false mismatch. Every accepted exchange must have exactly one balanced credit
    /// transaction, and every credit transaction must belong to exactly one accepted exchange.
    ///
    /// With `expected`, the chain must still contain that earlier head, so rollback at or before
    /// that checkpoint is detected. A first call without one establishes a baseline only: this
    /// service holds the audit key, so its verdict cannot prove absolute freshness.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] unless the actor is an auditor, before any read;
    /// [`ApplicationError::AuditIncomplete`] when the chain or the ledger exceeds the bound;
    /// [`ApplicationError::AuditMismatch`] with the first failing class, checked in the order
    /// chain, envelopes, credits.
    pub async fn verify_audit(
        &self,
        actor: &Actor,
        expected: Option<docchain_domain::Checkpoint>,
    ) -> Result<AuditReport, ApplicationError> {
        const CHAIN: ApplicationError = ApplicationError::AuditMismatch(AuditMismatch::EventChain);
        const ENVELOPE: ApplicationError =
            ApplicationError::AuditMismatch(AuditMismatch::EnvelopeCommitment);

        if *actor != Actor::Auditor {
            return Err(ApplicationError::Forbidden);
        }
        let credit_snapshot = self
            .adapters
            .audit_events()
            .credit_snapshot(self.limits.audit_events)
            .await
            .map_err(verify_read_error)?;
        let snapshot = credit_snapshot.snapshot;
        if snapshot.event_count() > u64::from(self.limits.audit_events) {
            return Err(ApplicationError::AuditIncomplete);
        }
        let mut after_sequence = 0;
        let mut events = Vec::new();
        loop {
            let stored = self
                .adapters
                .audit_events()
                .page(AuditReadRequest {
                    snapshot: Some(snapshot),
                    after_sequence,
                    limit: 500,
                })
                .await
                .map_err(verify_read_error)?;
            if stored.snapshot != snapshot {
                return Err(CHAIN);
            }
            // Every page must advance the cursor, so a faulty adapter cannot loop forever.
            let has_more = stored.has_more;
            let Some(last) = stored.events.last().map(|event| event.sequence) else {
                if has_more {
                    return Err(CHAIN);
                }
                break;
            };
            if last <= after_sequence {
                return Err(CHAIN);
            }
            after_sequence = last;
            events.extend(stored.events);
            if !has_more {
                break;
            }
        }
        if u64::try_from(events.len()).ok() != Some(snapshot.event_count()) {
            return Err(CHAIN);
        }
        let integrity = self.adapters.integrity();
        let head = verify_event_chain(&events, expected.as_ref(), |input, signature| {
            integrity.verify(input, signature).is_ok()
        })
        .map_err(|_| CHAIN)?;
        for event in &events {
            let envelope = self
                .adapters
                .documents()
                .get(&event.draft.object_id)
                .await
                .map_err(|error| match error {
                    StoreError::NotFound => ENVELOPE,
                    other => store_error(other),
                })?;
            if envelope_commitment(&envelope) != event.draft.envelope_commitment {
                return Err(ENVELOPE);
            }
            let header = self
                .adapters
                .crypto()
                .inspect(&envelope)
                .map_err(|_| ENVELOPE)?;
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
                return Err(ENVELOPE);
            }
        }
        let mut accepted = BTreeMap::new();
        for event in events
            .iter()
            .filter(|event| event.draft.kind == EventKind::Accepted)
        {
            if accepted
                .insert(event.draft.exchange_id.clone(), event.draft.sender.clone())
                .is_some()
            {
                return Err(CHAIN);
            }
        }
        let credits = reconcile_credits(&accepted, &credit_snapshot.transactions)
            .map_err(|mismatch| ApplicationError::AuditMismatch(mismatch.into()))?;
        Ok(AuditReport {
            event_count: events.len(),
            head,
            credits,
        })
    }

    /// Returns the pinned public half of the audit key to an authorized auditor.
    ///
    /// The returned fingerprint is not a trust anchor: a verifier compares it with the value
    /// provisioned to it separately and never adopts it from this response.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] unless the actor is an auditor.
    pub fn audit_public_key(&self, actor: &Actor) -> Result<AuditPublicKey, ApplicationError> {
        if *actor != Actor::Auditor {
            return Err(ApplicationError::Forbidden);
        }
        Ok(self.audit.public_key())
    }

    /// Selects or continues one bounded challenge-bound snapshot export.
    ///
    /// A start request selects the current snapshot and signs a manifest binding it to the
    /// verifier's challenge and the pinned key fingerprint. Every page repeats that manifest
    /// unchanged, and only the page that ends at the manifest's event count reports
    /// [`Coverage::Complete`]. Events appended after selection are excluded.
    ///
    /// A verifier's first complete export is a baseline. A later export detects rollback only at
    /// or before the newest checkpoint the verifier retained; neither proves absolute freshness
    /// nor that the key holder showed every auditor the same snapshot.
    ///
    /// # Errors
    ///
    /// [`ApplicationError::Forbidden`] unless the actor is an auditor, before any key or store
    /// access; [`ApplicationError::InvalidRequest`] for a manifest that is not signed by the
    /// pinned key; [`ApplicationError::AuditIncomplete`] for a snapshot beyond the configured
    /// total, with no page; [`ApplicationError::IntegrityFailure`] for a changed snapshot, a
    /// selected head whose signature fails or whose stored hash does not recompute from that
    /// head event's own preimage, or a stored event that fails its hash, link, or signature;
    /// [`ApplicationError::Unavailable`] when the store fails, including while a start reads
    /// the head. A start signs its manifest only after every one of these checks on the head
    /// and on the first page has passed, so a failed start signs nothing.
    pub async fn export_audit_events(
        &self,
        actor: &Actor,
        request: AuditExportRequest,
    ) -> Result<AuditExportPage, ApplicationError> {
        if *actor != Actor::Auditor {
            return Err(ApplicationError::Forbidden);
        }
        let limit = request.page_size(self.audit.default_page_size());
        let (manifest, signature, page) = match request.kind {
            AuditExportKind::Start { challenge } => {
                let stored = self
                    .adapters
                    .audit_events()
                    .page(AuditReadRequest {
                        snapshot: None,
                        after_sequence: 0,
                        limit,
                    })
                    .await
                    .map_err(audit_read_error)?;
                if stored.snapshot.event_count() > u64::from(self.audit.max_export_events()) {
                    return Err(ApplicationError::AuditIncomplete);
                }
                // The store is less trusted than the key: never attest to a head the key did
                // not sign, even when the first page stops before reaching it.
                if let Some(head) = stored.snapshot.head()
                    && self
                        .adapters
                        .integrity()
                        .verify(&event_signature_input(&head.event_hash), &head.signature)
                        .is_err()
                {
                    return Err(ApplicationError::IntegrityFailure);
                }
                if let Some(head) = stored.snapshot.head()
                    && stored.events.last().map(|event| event.sequence) != Some(head.sequence)
                {
                    self.check_head_preimage(stored.snapshot, head).await?;
                }
                let snapshot = stored.snapshot;
                let page = self.validate_page(snapshot, stored, 0, limit)?;
                let manifest = AuditExportManifest::new(
                    challenge,
                    self.audit.public_key().fingerprint().as_bytes(),
                    snapshot,
                );
                let signature = self
                    .adapters
                    .integrity()
                    .sign(&manifest.signature_input_v1())
                    .map_err(|_| ApplicationError::Invariant)?;
                (manifest, signature, page)
            }
            AuditExportKind::Continue {
                manifest,
                manifest_signature,
                after_sequence,
            } => {
                let manifest = *manifest;
                if manifest.audit_key_fingerprint()
                    != self.audit.public_key().fingerprint().as_bytes()
                    || self
                        .adapters
                        .integrity()
                        .verify(&manifest.signature_input_v1(), &manifest_signature)
                        .is_err()
                {
                    return Err(ApplicationError::InvalidRequest);
                }
                if manifest.snapshot().event_count() > u64::from(self.audit.max_export_events()) {
                    return Err(ApplicationError::AuditIncomplete);
                }
                let stored = self
                    .adapters
                    .audit_events()
                    .page(AuditReadRequest {
                        snapshot: Some(manifest.snapshot()),
                        after_sequence,
                        limit,
                    })
                    .await
                    .map_err(audit_read_error)?;
                let page =
                    self.validate_page(manifest.snapshot(), stored, after_sequence, limit)?;
                (manifest, manifest_signature, page)
            }
        };
        Ok(AuditExportPage {
            manifest,
            manifest_signature: signature,
            coverage: page.coverage,
            events: page.events,
            next_after_sequence: page.next_after_sequence,
        })
    }

    /// Proves that the selected head's stored hash recomputes from that head event's own
    /// preimage, for a first page that stops before the head. The head's signature is already
    /// verified, but the store could pair it with a hash taken from another sequence; the
    /// preimage binds the sequence, so a recomputing row at the head's own checkpoint cannot
    /// be such a moved hash.
    ///
    /// The head event is read only to recompute its hash and is then dropped.
    async fn check_head_preimage(
        &self,
        selected: AuditSnapshot,
        head: Checkpoint,
    ) -> Result<(), ApplicationError> {
        let read = self
            .adapters
            .audit_events()
            .page(AuditReadRequest {
                snapshot: Some(selected),
                after_sequence: head
                    .sequence
                    .checked_sub(1)
                    .ok_or(ApplicationError::IntegrityFailure)?,
                limit: 1,
            })
            .await
            .map_err(audit_read_error)?;
        let AuditStoredPage {
            snapshot,
            events,
            has_more,
        } = read;
        let [event] =
            <[AuditEvent; 1]>::try_from(events).map_err(|_| ApplicationError::IntegrityFailure)?;
        if snapshot != selected
            || has_more
            || event.sequence != head.sequence
            || event.checkpoint() != head
        {
            return Err(ApplicationError::IntegrityFailure);
        }
        AuditExportEvent::from_stored(event)?;
        Ok(())
    }

    /// Checks one stored page against the snapshot it must belong to, and converts it into
    /// exported proofs with its coverage markers. Nothing is signed here, so a start can run
    /// every check before its manifest is signed.
    fn validate_page(
        &self,
        snapshot: AuditSnapshot,
        stored: AuditStoredPage,
        after_sequence: u64,
        limit: u32,
    ) -> Result<ValidatedPage, ApplicationError> {
        if stored.snapshot != snapshot
            || stored.events.len()
                > usize::try_from(limit).map_err(|_| ApplicationError::Invariant)?
        {
            return Err(ApplicationError::IntegrityFailure);
        }
        let mut expected_sequence = after_sequence
            .checked_add(1)
            .ok_or(ApplicationError::InvalidRequest)?;
        // The chain starts from the all-zero hash; a continuation's link to the event before
        // its cursor is checked by the store inside the same snapshot read.
        let mut previous = (after_sequence == 0).then_some([0; 32]);
        let mut proof = Vec::with_capacity(stored.events.len());
        for event in stored.events {
            if event.sequence != expected_sequence
                || previous.is_some_and(|hash| event.previous_hash != hash)
                || event.sequence > snapshot.event_count()
                || (event.sequence == snapshot.event_count()
                    && snapshot.head() != Some(event.checkpoint()))
                || self
                    .adapters
                    .integrity()
                    .verify(&event_signature_input(&event.event_hash), &event.signature)
                    .is_err()
            {
                return Err(ApplicationError::IntegrityFailure);
            }
            previous = Some(event.event_hash);
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(ApplicationError::IntegrityFailure)?;
            proof.push(AuditExportEvent::from_stored(event)?);
        }
        let last = proof.last().map_or(after_sequence, |event| event.sequence);
        let (coverage, next_after_sequence) = page_markers(
            snapshot.event_count(),
            last,
            proof.len(),
            stored.has_more,
            limit,
        )?;
        Ok(ValidatedPage {
            coverage,
            events: proof,
            next_after_sequence,
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

/// A stored export page whose every event and marker has been checked, not yet bound to a
/// signed manifest.
struct ValidatedPage {
    coverage: Coverage,
    events: Vec<AuditExportEvent>,
    next_after_sequence: Option<u64>,
}

fn page_markers(
    event_count: u64,
    last_sequence: u64,
    returned: usize,
    has_more: bool,
    limit: u32,
) -> Result<(Coverage, Option<u64>), ApplicationError> {
    let complete = last_sequence == event_count;
    if has_more {
        if complete
            || returned != usize::try_from(limit).map_err(|_| ApplicationError::Invariant)?
        {
            return Err(ApplicationError::IntegrityFailure);
        }
        Ok((Coverage::Partial, Some(last_sequence)))
    } else if complete {
        Ok((Coverage::Complete, None))
    } else {
        Err(ApplicationError::IntegrityFailure)
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

fn audit_read_error(error: AuditReadError) -> ApplicationError {
    match error {
        AuditReadError::SnapshotChanged | AuditReadError::Invariant => {
            ApplicationError::IntegrityFailure
        }
        AuditReadError::Exhausted => ApplicationError::AuditIncomplete,
        AuditReadError::Transient | AuditReadError::Permanent => ApplicationError::Unavailable,
    }
}

/// Maps a read failure inside audit verification: a changed or broken snapshot is a chain
/// failure, and a ledger beyond the bound is an incomplete audit.
fn verify_read_error(error: AuditReadError) -> ApplicationError {
    match error {
        AuditReadError::SnapshotChanged | AuditReadError::Invariant => {
            ApplicationError::AuditMismatch(AuditMismatch::EventChain)
        }
        AuditReadError::Exhausted => ApplicationError::AuditIncomplete,
        AuditReadError::Transient | AuditReadError::Permanent => ApplicationError::Unavailable,
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
