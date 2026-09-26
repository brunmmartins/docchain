CREATE TABLE exchanges (
    exchange_id TEXT PRIMARY KEY,
    sender_wallet TEXT NOT NULL,
    recipient_wallet TEXT NOT NULL,
    document_id TEXT NOT NULL,
    document_version BIGINT NOT NULL CHECK (document_version > 0),
    request_nonce BYTEA NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    object_id TEXT NOT NULL UNIQUE,
    envelope_commitment BYTEA NOT NULL CHECK (octet_length(envelope_commitment) = 32),
    protected_hash BYTEA NOT NULL CHECK (octet_length(protected_hash) = 32),
    accepted BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (sender_wallet, request_nonce),
    UNIQUE (document_id, document_version, recipient_wallet)
);

CREATE TABLE audit_events (
    sequence BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('delivered', 'accepted')),
    exchange_id TEXT NOT NULL REFERENCES exchanges(exchange_id),
    object_id TEXT,
    commitment BYTEA NOT NULL CHECK (octet_length(commitment) = 32),
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    event_hash BYTEA NOT NULL CHECK (octet_length(event_hash) = 32)
);

CREATE TABLE acceptances (
    exchange_id TEXT PRIMARY KEY REFERENCES exchanges(exchange_id),
    idempotency_key TEXT NOT NULL UNIQUE
);

CREATE TABLE credits (
    eligibility_key TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL,
    amount BIGINT NOT NULL CHECK (amount = 1)
);
