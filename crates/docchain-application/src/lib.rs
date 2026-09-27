//! Application commands, authorization, and capability-oriented ports.

mod model;
mod ports;
mod service;

pub use model::{
    AcceptanceResult, Actor, ApplicationError, AuditExportEvent, AuditExportPage,
    AuditExportRequest, AuditKeyPin, AuditMismatch, AuditPublicKey, AuditReport, AuditSettings,
    Coverage, Credential, Delivery, Limits, Plaintext, SendCopyCommand,
};
pub use ports::{
    AcceptanceOutcome, Adapters, AuditCreditSnapshot, AuditEventStore, AuditReadError,
    AuditReadRequest, AuditStoredPage, Clock, CreditPosting, CryptoError, DocumentStore,
    EnvelopeCryptography, EnvelopeHeader, EventIntegrity, ExchangeRecord, ExchangeStore, HeaderKey,
    Identity, IdentityError, IntegrityError, KeyPurpose, KeyRegistry, KeyRegistryError,
    OpenRequest, SchemaArtifact, SchemaRegistry, SchemaRegistryError, SealRequest, SealedEnvelope,
    StoreError, VerifiedBinding,
};
pub use service::Application;
