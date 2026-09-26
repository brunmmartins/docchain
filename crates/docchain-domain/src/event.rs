//! The signed, hash-linked audit event chain.
//!
//! Each event commits to the exact stored ciphertext envelope, never to plaintext. Its hash
//! covers every field and the previous event's hash, and a separate audit key signs that hash.
//! A table writer without the audit key can therefore not alter, insert, remove, or reorder
//! events undetected, and an auditor holding an earlier signed head detects tail truncation.

use sha2::{Digest as _, Sha256};

use crate::{
    DocumentId, DocumentVersion, DomainError, ExchangeId, ObjectId, Timestamp, WalletId,
    types::MAX_SAFE_INTEGER,
};

const EVENT_LABEL: &[u8] = b"docchain/event/v1\0";
const EVENT_SIGNATURE_LABEL: &[u8] = b"docchain/event-signature/v1\0";

/// Computes SHA-256.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// The commitment an event records for a stored ciphertext envelope.
#[must_use]
pub fn envelope_commitment(envelope_bytes: &[u8]) -> [u8; 32] {
    sha256(envelope_bytes)
}

/// What an event records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// An encrypted copy was committed and delivered.
    Delivered,
    /// The recipient accepted a delivered copy.
    Accepted,
}

impl EventKind {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Accepted => "accepted",
        }
    }

    /// Parses the stored spelling.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EventIntegrity`] for any other value.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "delivered" => Ok(Self::Delivered),
            "accepted" => Ok(Self::Accepted),
            _ => Err(DomainError::EventIntegrity),
        }
    }
}

/// The fields of an event before the chain assigns its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDraft {
    /// What happened.
    pub kind: EventKind,
    /// The exchange it happened to.
    pub exchange_id: ExchangeId,
    /// The stored ciphertext envelope.
    pub object_id: ObjectId,
    /// SHA-256 of the exact stored envelope bytes.
    pub envelope_commitment: [u8; 32],
    /// The envelope format version.
    pub envelope_version: u32,
    /// SHA-256 of the envelope's protected header.
    pub protected_hash: [u8; 32],
    /// The sending wallet.
    pub sender: WalletId,
    /// The receiving wallet.
    pub recipient: WalletId,
    /// The exchanged document.
    pub document_id: DocumentId,
    /// The exchanged document version.
    pub document_version: DocumentVersion,
    /// The key-registry sequence at which the bindings were checked.
    pub registry_sequence: u64,
    /// When the send read the clock and checked its keys; historic key state is judged then.
    /// An acceptance event carries its exchange's value.
    pub committed_at: Timestamp,
}

/// One signed event in the chain.
///
/// Fields are public so stored rows can be mapped and verified; [`verify_event_chain`] is what
/// establishes that a sequence of events is authentic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Position in the chain, starting at 1.
    pub sequence: u64,
    /// The recorded fields.
    pub draft: EventDraft,
    /// The previous event's hash, or zeros for the first event.
    pub previous_hash: [u8; 32],
    /// SHA-256 over the canonical event bytes.
    pub event_hash: [u8; 32],
    /// The audit key's Ed25519 signature over [`event_signature_input`].
    pub signature: [u8; 64],
}

/// A signed chain head an auditor keeps to detect later truncation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Sequence of the head event.
    pub sequence: u64,
    /// Hash of the head event.
    pub event_hash: [u8; 32],
    /// The audit key's signature over the head event.
    pub signature: [u8; 64],
}

impl AuditEvent {
    /// Places a draft at `sequence` after `previous_hash` and returns its event hash.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EventIntegrity`] when the sequence is zero or outside the exact
    /// integer range, or a field cannot be length-prefixed.
    pub fn hash_for(
        draft: &EventDraft,
        sequence: u64,
        previous_hash: &[u8; 32],
    ) -> Result<[u8; 32], DomainError> {
        Ok(sha256(&canonical_bytes(draft, sequence, previous_hash)?))
    }

    /// Assembles a signed event from a draft, its position, and the audit signature.
    ///
    /// # Errors
    ///
    /// As [`AuditEvent::hash_for`].
    pub fn assemble(
        draft: EventDraft,
        sequence: u64,
        previous_hash: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self, DomainError> {
        let event_hash = Self::hash_for(&draft, sequence, &previous_hash)?;
        Ok(Self {
            sequence,
            draft,
            previous_hash,
            event_hash,
            signature,
        })
    }

    /// The head checkpoint this event represents.
    #[must_use]
    pub const fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            sequence: self.sequence,
            event_hash: self.event_hash,
            signature: self.signature,
        }
    }
}

/// The bytes the audit key signs for an event hash.
#[must_use]
pub fn event_signature_input(event_hash: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(EVENT_SIGNATURE_LABEL.len() + 32);
    input.extend_from_slice(EVENT_SIGNATURE_LABEL);
    input.extend_from_slice(event_hash);
    input
}

fn canonical_bytes(
    draft: &EventDraft,
    sequence: u64,
    previous_hash: &[u8; 32],
) -> Result<Vec<u8>, DomainError> {
    if sequence == 0 || sequence > MAX_SAFE_INTEGER {
        return Err(DomainError::EventIntegrity);
    }
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVENT_LABEL);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    push_field(&mut bytes, draft.kind.as_str().as_bytes())?;
    push_field(&mut bytes, draft.exchange_id.as_str().as_bytes())?;
    push_field(&mut bytes, draft.object_id.as_str().as_bytes())?;
    bytes.extend_from_slice(&draft.envelope_commitment);
    bytes.extend_from_slice(&draft.envelope_version.to_be_bytes());
    bytes.extend_from_slice(&draft.protected_hash);
    push_field(&mut bytes, draft.sender.as_str().as_bytes())?;
    push_field(&mut bytes, draft.recipient.as_str().as_bytes())?;
    push_field(&mut bytes, draft.document_id.as_str().as_bytes())?;
    bytes.extend_from_slice(&draft.document_version.get().to_be_bytes());
    bytes.extend_from_slice(&draft.registry_sequence.to_be_bytes());
    bytes.extend_from_slice(&draft.committed_at.unix_seconds().to_be_bytes());
    bytes.extend_from_slice(previous_hash);
    Ok(bytes)
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), DomainError> {
    let length = u32::try_from(value.len()).map_err(|_| DomainError::EventIntegrity)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Verifies a complete chain in sequence order and returns its head.
///
/// Checks that sequences run 1, 2, 3, … without gaps, that each event links to the previous
/// hash, that each hash matches the event's fields, and that `verify_signature(input,
/// signature)` accepts every event. When `expected` is given, the chain must still contain that
/// previously observed head at its sequence, detecting truncation at or before that checkpoint.
///
/// # Errors
///
/// Returns [`DomainError::EventIntegrity`] on the first failed check.
pub fn verify_event_chain(
    events: &[AuditEvent],
    expected: Option<&Checkpoint>,
    verify_signature: impl Fn(&[u8], &[u8; 64]) -> bool,
) -> Result<Option<Checkpoint>, DomainError> {
    let mut previous = [0; 32];
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or(DomainError::EventIntegrity)?;
        if event.sequence != expected_sequence
            || event.previous_hash != previous
            || AuditEvent::hash_for(&event.draft, event.sequence, &event.previous_hash)?
                != event.event_hash
            || !verify_signature(&event_signature_input(&event.event_hash), &event.signature)
        {
            return Err(DomainError::EventIntegrity);
        }
        previous = event.event_hash;
    }
    if let Some(expected) = expected {
        let held = usize::try_from(expected.sequence)
            .ok()
            .and_then(|sequence| sequence.checked_sub(1))
            .and_then(|index| events.get(index))
            .ok_or(DomainError::EventIntegrity)?;
        if held.event_hash != expected.event_hash || held.signature != expected.signature {
            return Err(DomainError::EventIntegrity);
        }
    }
    Ok(events.last().map(AuditEvent::checkpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in keyed signature: SHA-256 over a secret and the input, twice.
    fn sign(input: &[u8]) -> [u8; 64] {
        let first = sha256(&[b"test-audit-key".as_slice(), input].concat());
        let second = sha256(&first);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&first);
        signature[32..].copy_from_slice(&second);
        signature
    }

    fn verify(input: &[u8], signature: &[u8; 64]) -> bool {
        &sign(input) == signature
    }

    fn draft(kind: EventKind, commitment: u8) -> EventDraft {
        EventDraft {
            kind,
            exchange_id: ExchangeId::new("exc_0123456789abcdef").expect("id"),
            object_id: ObjectId::new("obj_0123456789abcdef").expect("id"),
            envelope_commitment: [commitment; 32],
            envelope_version: 1,
            protected_hash: [9; 32],
            sender: WalletId::new("wal_0000000000000001").expect("id"),
            recipient: WalletId::new("wal_0000000000000002").expect("id"),
            document_id: DocumentId::new("doc_0000000000000001").expect("id"),
            document_version: DocumentVersion::new(1).expect("version"),
            registry_sequence: 3,
            committed_at: Timestamp::from_unix_seconds(1_790_000_000),
        }
    }

    fn chain(length: u8) -> Vec<AuditEvent> {
        let mut events: Vec<AuditEvent> = Vec::new();
        for index in 0..length {
            let previous = events.last().map_or([0; 32], |event| event.event_hash);
            let sequence = u64::from(index) + 1;
            let draft = draft(EventKind::Delivered, index);
            let hash = AuditEvent::hash_for(&draft, sequence, &previous).expect("hash");
            let signature = sign(&event_signature_input(&hash));
            events.push(AuditEvent::assemble(draft, sequence, previous, signature).expect("event"));
        }
        events
    }

    #[test]
    fn verifies_an_intact_chain_and_returns_its_head() {
        let events = chain(3);
        let head = verify_event_chain(&events, None, verify).expect("intact chain");
        assert_eq!(head, Some(events[2].checkpoint()));
        assert_eq!(
            verify_event_chain(&events, Some(&events[1].checkpoint()), verify),
            Ok(head)
        );
        assert_eq!(verify_event_chain(&[], None, verify), Ok(None));
    }

    #[test]
    fn detects_alteration_insertion_removal_reordering_and_truncation() {
        let events = chain(3);
        let mut altered = events.clone();
        altered[1].draft.envelope_commitment[0] ^= 1;
        let mut rehashed = events.clone();
        rehashed[1].draft.registry_sequence = 4;
        rehashed[1].event_hash = AuditEvent::hash_for(
            &rehashed[1].draft,
            rehashed[1].sequence,
            &rehashed[1].previous_hash,
        )
        .expect("hash");
        let mut inserted = events.clone();
        inserted.insert(1, events[1].clone());
        let mut reordered = events.clone();
        reordered.swap(1, 2);
        let mut removed_middle = events.clone();
        removed_middle.remove(1);
        let truncated = events[..2].to_vec();
        let expected_head = events[2].checkpoint();

        for (case, candidate, expected) in [
            ("alteration", altered, None),
            ("recomputed hash without the key", rehashed, None),
            ("insertion", inserted, None),
            ("reordering", reordered, None),
            ("middle removal", removed_middle, None),
            ("tail truncation", truncated, Some(&expected_head)),
        ] {
            assert_eq!(
                verify_event_chain(&candidate, expected, verify),
                Err(DomainError::EventIntegrity),
                "{case}"
            );
        }
    }

    #[test]
    fn commit_time_is_part_of_the_event_hash() {
        let sent = draft(EventKind::Delivered, 1);
        let mut later = sent.clone();
        later.committed_at = Timestamp::from_unix_seconds(sent.committed_at.unix_seconds() + 1);
        assert_ne!(
            AuditEvent::hash_for(&sent, 1, &[0; 32]),
            AuditEvent::hash_for(&later, 1, &[0; 32])
        );

        let mut events = chain(3);
        events[1].draft.committed_at = later.committed_at;
        assert_eq!(
            verify_event_chain(&events, None, verify),
            Err(DomainError::EventIntegrity)
        );
    }
}
