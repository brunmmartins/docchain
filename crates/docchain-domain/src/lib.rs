//! Infrastructure-independent types, strict JSON, schema validation, and event integrity.

mod event;
mod json;
mod pattern;
mod schema;
mod time;
mod types;

pub use event::{
    AUDIT_PREIMAGE_VERSION, AuditChallenge, AuditEvent, AuditExportManifest, AuditSnapshot,
    Checkpoint, EventDraft, EventKind, envelope_commitment, event_signature_input, sha256,
    verify_event_chain,
};
pub use json::{CanonicalDocument, canonicalize, parse_bounded_json, parse_document};
pub use schema::CompiledSchema;
pub use time::Timestamp;
pub use types::{
    DocumentId, DocumentVersion, DomainError, ExchangeId, IdempotencyKey, MAX_DOCUMENT_BYTES,
    MAX_JSON_DEPTH, MAX_SAFE_INTEGER, ObjectId, RequestNonce, WalletId,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_object_names() {
        assert_eq!(
            parse_document(br#"{"a":1,"a":2}"#).expect_err("duplicate"),
            DomainError::InvalidJson
        );
    }

    #[test]
    fn rejects_fractional_lossy_and_invalid_text() {
        assert!(parse_document(br#"{"n":1.0}"#).is_err());
        assert!(parse_document(br#"{"n":1e3}"#).is_err());
        assert!(parse_document(br#"{"n":9007199254740992}"#).is_err());
        assert!(parse_document(br#"{"s":"\ud800"}"#).is_err());
        assert!(parse_document(b"{\"s\":\"\xff\"}").is_err());
    }

    #[test]
    fn rejects_depth_and_size_beyond_bounds() {
        let deep = format!("{}{}", "[".repeat(33), "]".repeat(33));
        assert!(parse_document(deep.as_bytes()).is_err());
        let fits = format!("{}{}", "[".repeat(32), "]".repeat(32));
        assert!(parse_document(fits.as_bytes()).is_ok());
        let large = format!("\"{}\"", "a".repeat(MAX_DOCUMENT_BYTES));
        assert_eq!(
            parse_document(large.as_bytes()).map(|_| ()),
            Err(DomainError::Bound("raw document size"))
        );
    }

    #[test]
    fn canonicalizes_property_order() {
        let document = parse_document(br#"{"z":1,"a":2}"#).expect("strict JSON");
        assert_eq!(document.bytes(), br#"{"a":2,"z":1}"#);
    }

    #[test]
    fn document_debug_output_is_redacted() {
        let document = parse_document(br#"{"secret":"Please provide"}"#).expect("strict JSON");
        assert_eq!(format!("{document:?}"), "CanonicalDocument(redacted)");
    }

    #[test]
    fn document_versions_are_positive_exact_integers() {
        assert!(DocumentVersion::new(0).is_err());
        assert!(DocumentVersion::new(MAX_SAFE_INTEGER + 1).is_err());
        assert_eq!(DocumentVersion::new(7).map(DocumentVersion::get), Ok(7));
    }
}
