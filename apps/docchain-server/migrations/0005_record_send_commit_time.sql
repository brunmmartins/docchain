-- Each exchange and event records when its send read the clock and checked its keys, in whole
-- seconds since the Unix epoch, so later reads judge historic key state at that instant.
-- No true value exists for a row stored before this column, and a default or backfill would
-- invent one. The migration therefore refuses a schema that already holds exchanges or events.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM exchanges) OR EXISTS (SELECT 1 FROM audit_events) THEN
        RAISE EXCEPTION 'stored exchanges have no recorded commit time'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

ALTER TABLE exchanges ADD COLUMN committed_at BIGINT NOT NULL CHECK (committed_at >= 0);

ALTER TABLE audit_events ADD COLUMN committed_at BIGINT NOT NULL CHECK (committed_at >= 0);
