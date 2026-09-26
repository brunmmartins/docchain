ALTER TABLE exchanges
    DROP CONSTRAINT exchanges_idempotency_key_key,
    ADD COLUMN schema_id TEXT NOT NULL DEFAULT 'urn:docchain:schema:service-application:1.0.0',
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT '1.0.0',
    ADD COLUMN envelope_version INTEGER NOT NULL DEFAULT 1 CHECK (envelope_version = 1),
    ADD COLUMN registry_sequence BIGINT NOT NULL DEFAULT 0 CHECK (registry_sequence >= 0),
    ADD CONSTRAINT exchanges_sender_idempotency_key UNIQUE (sender_wallet, idempotency_key);

ALTER TABLE audit_events
    ALTER COLUMN object_id SET NOT NULL,
    ADD COLUMN envelope_version INTEGER NOT NULL DEFAULT 1 CHECK (envelope_version = 1),
    ADD COLUMN protected_hash BYTEA NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(protected_hash) = 32),
    ADD COLUMN sender_wallet TEXT NOT NULL DEFAULT 'wal_0000000000000000',
    ADD COLUMN recipient_wallet TEXT NOT NULL DEFAULT 'wal_0000000000000000',
    ADD COLUMN document_id TEXT NOT NULL DEFAULT 'doc_0000000000000000',
    ADD COLUMN document_version BIGINT NOT NULL DEFAULT 1 CHECK (document_version > 0),
    ADD COLUMN registry_sequence BIGINT NOT NULL DEFAULT 0 CHECK (registry_sequence >= 0),
    ADD COLUMN signature BYTEA NOT NULL DEFAULT decode(repeat('00', 64), 'hex')
        CHECK (octet_length(signature) = 64);

CREATE TABLE credit_transactions (
    eligibility_key TEXT PRIMARY KEY,
    exchange_id TEXT NOT NULL UNIQUE REFERENCES exchanges(exchange_id)
);

CREATE TABLE credit_entries (
    eligibility_key TEXT NOT NULL REFERENCES credit_transactions(eligibility_key),
    account_id TEXT NOT NULL,
    amount BIGINT NOT NULL CHECK (amount IN (-1, 1)),
    PRIMARY KEY (eligibility_key, account_id)
);

CREATE INDEX credit_entries_account ON credit_entries(account_id);
