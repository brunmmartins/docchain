use std::fmt;

use thiserror::Error;

/// Largest raw or canonical document accepted, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
/// Deepest JSON nesting accepted in a document.
pub const MAX_JSON_DEPTH: usize = 32;
/// Largest integer the strict JSON profile accepts, in absolute value.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Failures of domain validation and integrity rules.
///
/// Variants carry no document content, so they are safe to log or return.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// An identifier did not match its syntax.
    #[error("invalid {kind}")]
    InvalidIdentifier {
        /// Which identifier failed.
        kind: &'static str,
    },
    /// The input is not strict-profile JSON.
    #[error("invalid strict-profile JSON")]
    InvalidJson,
    /// The input breaches a size or depth bound.
    #[error("JSON exceeds the {0} bound")]
    Bound(&'static str),
    /// The document does not satisfy its schema.
    #[error("document does not satisfy the active schema")]
    Schema,
    /// The schema artifact uses a feature this validator does not support, or is malformed.
    #[error("unsupported schema artifact")]
    UnsupportedSchema,
    /// A timestamp is not canonical UTC RFC 3339 seconds.
    #[error("invalid timestamp")]
    InvalidTimestamp,
    /// An event field cannot be encoded, or the chain does not verify.
    #[error("event chain integrity failure")]
    EventIntegrity,
}

macro_rules! bounded_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validates `", $prefix, "` followed by 16 to 64 lowercase ASCII letters or digits.")]
            ///
            /// # Errors
            ///
            /// Returns [`DomainError::InvalidIdentifier`] for any other value.
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                let suffix = value
                    .strip_prefix($prefix)
                    .ok_or(DomainError::InvalidIdentifier { kind: $kind })?;
                if !(16..=64).contains(&suffix.len())
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                {
                    return Err(DomainError::InvalidIdentifier { kind: $kind });
                }
                Ok(Self(value))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($kind, "(redacted)"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_id!(
    /// A synthetic wallet.
    WalletId,
    "wal_",
    "wallet id"
);
bounded_id!(
    /// A document whose versions are exchanged.
    DocumentId,
    "doc_",
    "document id"
);
bounded_id!(
    /// A client-chosen key that makes one operation idempotent for one wallet.
    IdempotencyKey,
    "idem_",
    "idempotency key"
);
bounded_id!(
    /// One committed exchange.
    ExchangeId,
    "exc_",
    "exchange id"
);
bounded_id!(
    /// One stored ciphertext envelope.
    ObjectId,
    "obj_",
    "object id"
);

/// A positive document version within the exact JSON integer range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DocumentVersion(u64);

impl DocumentVersion {
    /// Validates a version from 1 through 9007199254740991.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidIdentifier`] outside that range.
    pub const fn new(value: u64) -> Result<Self, DomainError> {
        if value == 0 || value > MAX_SAFE_INTEGER {
            return Err(DomainError::InvalidIdentifier {
                kind: "document version",
            });
        }
        Ok(Self(value))
    }

    /// Returns the version number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The 16-byte nonce a sender binds to one request.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestNonce([u8; 16]);

impl RequestNonce {
    /// Wraps the nonce bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for RequestNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestNonce(redacted)")
    }
}
