-- An acceptance idempotency key belongs to the accepting wallet, as a send key belongs to the sender,
-- so one wallet's key can never collide with another wallet's acceptance.
ALTER TABLE acceptances ADD COLUMN recipient_wallet TEXT;

UPDATE acceptances AS acceptance
SET recipient_wallet = exchange.recipient_wallet
FROM exchanges AS exchange
WHERE exchange.exchange_id = acceptance.exchange_id;

ALTER TABLE acceptances
    ALTER COLUMN recipient_wallet SET NOT NULL,
    DROP CONSTRAINT acceptances_idempotency_key_key,
    ADD CONSTRAINT acceptances_recipient_idempotency_key UNIQUE (recipient_wallet, idempotency_key);

-- Balanced credit transactions replace the single-entry credit rows, which nothing writes.
DROP TABLE credits;

-- Every credit transaction is exactly one debit and one credit that sum to zero, checked when the
-- database transaction commits so both entries can be inserted first.
CREATE FUNCTION credit_transaction_is_balanced() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    checked_key TEXT;
    entry_count BIGINT;
    entry_total BIGINT;
    debit_count BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        checked_key := OLD.eligibility_key;
    ELSE
        checked_key := NEW.eligibility_key;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM credit_transactions WHERE eligibility_key = checked_key) THEN
        RETURN NULL;
    END IF;
    SELECT COUNT(*), COALESCE(SUM(amount), 0), COUNT(*) FILTER (WHERE amount < 0)
    INTO entry_count, entry_total, debit_count
    FROM credit_entries
    WHERE eligibility_key = checked_key;
    IF entry_count <> 2 OR entry_total <> 0 OR debit_count <> 1 THEN
        RAISE EXCEPTION 'credit transaction is not one balanced debit and credit'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER credit_entries_balanced
    AFTER INSERT OR UPDATE OR DELETE ON credit_entries
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION credit_transaction_is_balanced();

CREATE CONSTRAINT TRIGGER credit_transactions_balanced
    AFTER INSERT OR UPDATE ON credit_transactions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION credit_transaction_is_balanced();
