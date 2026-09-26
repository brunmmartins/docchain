ALTER TABLE exchanges
    DROP CONSTRAINT exchanges_document_id_document_version_recipient_wallet_key,
    ADD CONSTRAINT exchanges_sender_document_recipient_key
        UNIQUE (sender_wallet, document_id, document_version, recipient_wallet),
    ALTER COLUMN schema_id DROP DEFAULT,
    ALTER COLUMN schema_version DROP DEFAULT,
    ALTER COLUMN envelope_version DROP DEFAULT,
    ALTER COLUMN registry_sequence DROP DEFAULT;

ALTER TABLE audit_events
    ALTER COLUMN envelope_version DROP DEFAULT,
    ALTER COLUMN protected_hash DROP DEFAULT,
    ALTER COLUMN sender_wallet DROP DEFAULT,
    ALTER COLUMN recipient_wallet DROP DEFAULT,
    ALTER COLUMN document_id DROP DEFAULT,
    ALTER COLUMN document_version DROP DEFAULT,
    ALTER COLUMN registry_sequence DROP DEFAULT,
    ALTER COLUMN signature DROP DEFAULT;

CREATE FUNCTION refuse_append_only_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'append-only relation cannot be changed'
        USING ERRCODE = '23001';
END;
$$;

CREATE TRIGGER audit_events_refuse_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION refuse_append_only_mutation();
CREATE TRIGGER audit_events_refuse_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_append_only_mutation();
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_refuse_update_delete;
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_refuse_truncate;

CREATE TRIGGER acceptances_refuse_update_delete
    BEFORE UPDATE OR DELETE ON acceptances
    FOR EACH ROW EXECUTE FUNCTION refuse_append_only_mutation();
CREATE TRIGGER acceptances_refuse_truncate
    BEFORE TRUNCATE ON acceptances
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_append_only_mutation();
ALTER TABLE acceptances ENABLE ALWAYS TRIGGER acceptances_refuse_update_delete;
ALTER TABLE acceptances ENABLE ALWAYS TRIGGER acceptances_refuse_truncate;

CREATE TRIGGER credit_transactions_refuse_update_delete
    BEFORE UPDATE OR DELETE ON credit_transactions
    FOR EACH ROW EXECUTE FUNCTION refuse_append_only_mutation();
CREATE TRIGGER credit_transactions_refuse_truncate
    BEFORE TRUNCATE ON credit_transactions
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_append_only_mutation();
ALTER TABLE credit_transactions ENABLE ALWAYS TRIGGER credit_transactions_refuse_update_delete;
ALTER TABLE credit_transactions ENABLE ALWAYS TRIGGER credit_transactions_refuse_truncate;

CREATE TRIGGER credit_entries_refuse_update_delete
    BEFORE UPDATE OR DELETE ON credit_entries
    FOR EACH ROW EXECUTE FUNCTION refuse_append_only_mutation();
CREATE TRIGGER credit_entries_refuse_truncate
    BEFORE TRUNCATE ON credit_entries
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_append_only_mutation();
ALTER TABLE credit_entries ENABLE ALWAYS TRIGGER credit_entries_refuse_update_delete;
ALTER TABLE credit_entries ENABLE ALWAYS TRIGGER credit_entries_refuse_truncate;
