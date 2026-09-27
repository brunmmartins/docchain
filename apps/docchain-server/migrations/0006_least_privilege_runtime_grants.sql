-- The server runs as a separate runtime role that holds exactly the privileges it needs, and
-- nothing that could change a table, a trigger, a function, or the migration ledger.
--
-- The runtime role's name comes from the connection setting `docchain.runtime_role`, which the
-- migrator sets, so this file names no role. The migration refuses to run, and leaves this
-- version unapplied, unless the migrating role owns the schema and everything in it, the schema
-- is not `public`, and the runtime role satisfies the principal part of the runtime privilege
-- rule. It rolls back unless the whole rule holds after granting.

-- Preconditions. Any failure raises and rolls this migration back.
DO $precondition$
DECLARE
    runtime_name TEXT := current_setting('docchain.runtime_role', true);
    runtime_oid OID;
    migrating_oid OID := (SELECT oid FROM pg_roles WHERE rolname = current_user);
    schema_oid OID := (SELECT oid FROM pg_namespace WHERE nspname = current_schema());
BEGIN
    IF runtime_name IS NULL OR runtime_name = '' THEN
        RAISE EXCEPTION 'docchain.runtime_role is not set' USING ERRCODE = '22023';
    END IF;
    runtime_oid := (SELECT oid FROM pg_roles WHERE rolname = runtime_name);
    IF runtime_oid IS NULL THEN
        RAISE EXCEPTION 'docchain.runtime_role names no role' USING ERRCODE = '22023';
    END IF;
    IF runtime_oid = migrating_oid THEN
        RAISE EXCEPTION 'the runtime role must differ from the migrating role'
            USING ERRCODE = '22023';
    END IF;
    IF schema_oid IS NULL OR current_schema() = 'public' THEN
        RAISE EXCEPTION 'migrations need a schema of their own, not public'
            USING ERRCODE = '42501';
    END IF;
    -- Ownership is compared by exact role identity, never by membership.
    IF (SELECT nspowner FROM pg_namespace WHERE oid = schema_oid) <> migrating_oid
        OR EXISTS (
            SELECT 1 FROM pg_class
            WHERE relnamespace = schema_oid AND relowner <> migrating_oid
        )
        OR EXISTS (
            SELECT 1 FROM pg_proc
            WHERE pronamespace = schema_oid AND proowner <> migrating_oid
        )
    THEN
        RAISE EXCEPTION 'the migrating role must own the schema and everything in it'
            USING ERRCODE = '42501';
    END IF;
    -- The principal part of the runtime privilege rule.
    IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE oid = runtime_oid
                AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
        )
        OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = runtime_oid)
        OR EXISTS (
            SELECT 1 FROM pg_database
            WHERE datname = current_database() AND datdba = runtime_oid
        )
        OR EXISTS (
            SELECT 1 FROM pg_shdepend
            WHERE refclassid = 'pg_authid'::regclass AND refobjid = runtime_oid AND deptype = 'o'
        )
        OR EXISTS (
            SELECT 1 FROM pg_parameter_acl, aclexplode(paracl) AS entry
            WHERE entry.grantee IN (runtime_oid, 0)
        )
        OR has_database_privilege(runtime_oid, current_database(), 'CREATE')
        OR EXISTS (SELECT 1 FROM pg_db_role_setting WHERE setrole = runtime_oid)
    THEN
        RAISE EXCEPTION 'the runtime role breaks the runtime privilege rule'
            USING ERRCODE = '42501';
    END IF;
END;
$precondition$;

DO $grants$
DECLARE
    runtime_name TEXT := current_setting('docchain.runtime_role');
    schema_name TEXT := current_schema();
    insertable TEXT;
BEGIN
    -- 1. An accepted exchange stays accepted, whatever the session replication role.
    EXECUTE format(
        $function$
        CREATE FUNCTION %1$I.refuse_acceptance_reset() RETURNS trigger
        LANGUAGE plpgsql SET search_path = %1$I, pg_temp AS $body$
        BEGIN
            IF OLD.accepted AND NOT NEW.accepted THEN
                RAISE EXCEPTION 'an accepted exchange cannot be reset'
                    USING ERRCODE = '23001';
            END IF;
            RETURN NEW;
        END;
        $body$
        $function$,
        schema_name
    );
    EXECUTE format(
        'CREATE TRIGGER exchanges_acceptance_is_one_way '
        'BEFORE UPDATE OF accepted ON %1$I.exchanges '
        'FOR EACH ROW EXECUTE FUNCTION %1$I.refuse_acceptance_reset()',
        schema_name
    );
    EXECUTE format(
        'ALTER TABLE %I.exchanges ENABLE ALWAYS TRIGGER exchanges_acceptance_is_one_way',
        schema_name
    );

    -- 2. Nothing is held on the schema or its objects except what step 3 grants. Revoking a
    -- table privilege also revokes the matching column privileges.
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC, %I', schema_name, runtime_name);
    EXECUTE format(
        'REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC, %I', schema_name, runtime_name
    );
    EXECUTE format(
        'REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM PUBLIC, %I', schema_name, runtime_name
    );
    EXECUTE format(
        'REVOKE ALL ON ALL ROUTINES IN SCHEMA %I FROM PUBLIC, %I', schema_name, runtime_name
    );

    -- 3. Exactly the runtime matrix. Every event insert supplies its sequence, and triggers
    -- fire without EXECUTE on their functions, so no sequence or function privilege is granted.
    -- The balance trigger runs as the invoker and reads both credit tables.
    SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum)
    INTO insertable
    FROM pg_attribute
    WHERE attrelid = format('%I.exchanges', schema_name)::regclass
        AND attnum > 0 AND NOT attisdropped AND attname <> 'accepted';
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, runtime_name);
    EXECUTE format('GRANT SELECT ON %I.exchanges TO %I', schema_name, runtime_name);
    EXECUTE format(
        'GRANT INSERT (%s) ON %I.exchanges TO %I', insertable, schema_name, runtime_name
    );
    EXECUTE format('GRANT UPDATE (accepted) ON %I.exchanges TO %I', schema_name, runtime_name);
    EXECUTE format('GRANT SELECT, INSERT ON %I.audit_events TO %I', schema_name, runtime_name);
    EXECUTE format('GRANT INSERT ON %I.acceptances TO %I', schema_name, runtime_name);
    EXECUTE format(
        'GRANT SELECT, INSERT ON %I.credit_transactions TO %I', schema_name, runtime_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT ON %I.credit_entries TO %I', schema_name, runtime_name
    );
    EXECUTE format('GRANT SELECT ON %I._sqlx_migrations TO %I', schema_name, runtime_name);

    -- 4. Trigger functions resolve names in this schema only, never in a session's temporary
    -- tables.
    EXECUTE format(
        'ALTER FUNCTION %1$I.credit_transaction_is_balanced() SET search_path = %1$I, pg_temp',
        schema_name
    );
    EXECUTE format(
        'ALTER FUNCTION %1$I.refuse_append_only_mutation() SET search_path = %1$I, pg_temp',
        schema_name
    );
END;
$grants$;

-- 5. The balance triggers fire whatever the session replication role.
ALTER TABLE credit_entries ENABLE ALWAYS TRIGGER credit_entries_balanced;
ALTER TABLE credit_transactions ENABLE ALWAYS TRIGGER credit_transactions_balanced;

-- Postcondition: the whole runtime privilege rule, every trigger always enabled, and every
-- function's search path pinned. Any failure rolls this migration back.
DO $postcondition$
DECLARE
    runtime_oid OID := (
        SELECT oid FROM pg_roles WHERE rolname = current_setting('docchain.runtime_role')
    );
    schema_oid OID := (SELECT oid FROM pg_namespace WHERE nspname = current_schema());
    differences BIGINT;
BEGIN
    IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE oid = runtime_oid
                AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
        )
        OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = runtime_oid)
        OR EXISTS (
            SELECT 1 FROM pg_database
            WHERE datname = current_database() AND datdba = runtime_oid
        )
        OR EXISTS (
            SELECT 1 FROM pg_shdepend
            WHERE refclassid = 'pg_authid'::regclass AND refobjid = runtime_oid AND deptype = 'o'
        )
        OR EXISTS (
            SELECT 1 FROM pg_parameter_acl, aclexplode(paracl) AS entry
            WHERE entry.grantee IN (runtime_oid, 0)
        )
        OR has_database_privilege(runtime_oid, current_database(), 'CREATE')
        OR EXISTS (SELECT 1 FROM pg_db_role_setting WHERE setrole = runtime_oid)
    THEN
        RAISE EXCEPTION 'the runtime role breaks the runtime privilege rule'
            USING ERRCODE = '42501';
    END IF;

    WITH matrix(kind, relation, column_rule, privilege) AS (
        -- runtime privilege matrix
        VALUES
            ('schema', '', '', 'USAGE'),
            ('table', 'exchanges', '', 'SELECT'),
            ('columns except', 'exchanges', 'accepted', 'INSERT'),
            ('columns only', 'exchanges', 'accepted', 'UPDATE'),
            ('table', 'audit_events', '', 'SELECT'),
            ('table', 'audit_events', '', 'INSERT'),
            ('table', 'acceptances', '', 'INSERT'),
            ('table', 'credit_transactions', '', 'SELECT'),
            ('table', 'credit_transactions', '', 'INSERT'),
            ('table', 'credit_entries', '', 'SELECT'),
            ('table', 'credit_entries', '', 'INSERT'),
            ('table', '_sqlx_migrations', '', 'SELECT')
        -- end of runtime privilege matrix
    ),
    relations AS (
        SELECT oid, relname::text AS name, relkind
        FROM pg_class
        WHERE relnamespace = schema_oid AND relkind IN ('r', 'v', 'm', 'f', 'p', 'S')
    ),
    live_columns AS (
        SELECT relations.oid, relations.name, attribute.attnum,
            attribute.attname::text AS column_name
        FROM relations
        JOIN pg_attribute AS attribute
            ON attribute.attrelid = relations.oid
            AND attribute.attnum > 0 AND NOT attribute.attisdropped
        WHERE relations.relkind <> 'S'
    ),
    held(kind, object, column_name, privilege, grantable) AS (
        SELECT 'schema', '', '', held_privilege,
            has_schema_privilege(runtime_oid, schema_oid, held_privilege || ' WITH GRANT OPTION')
        FROM unnest(ARRAY['USAGE', 'CREATE']) AS held_privilege
        WHERE has_schema_privilege(runtime_oid, schema_oid, held_privilege)
        UNION ALL
        SELECT 'table', relations.name, '', held_privilege,
            has_table_privilege(runtime_oid, relations.oid, held_privilege || ' WITH GRANT OPTION')
        FROM relations, unnest(ARRAY[
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'
        ]) AS held_privilege
        WHERE relations.relkind <> 'S'
            AND has_table_privilege(runtime_oid, relations.oid, held_privilege)
        UNION ALL
        SELECT 'column', live_columns.name, live_columns.column_name, held_privilege,
            has_column_privilege(
                runtime_oid, live_columns.oid, live_columns.attnum,
                held_privilege || ' WITH GRANT OPTION'
            )
        FROM live_columns, unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES'])
            AS held_privilege
        WHERE has_column_privilege(
            runtime_oid, live_columns.oid, live_columns.attnum, held_privilege
        )
        UNION ALL
        SELECT 'sequence', relations.name, '', held_privilege,
            has_sequence_privilege(
                runtime_oid, relations.oid, held_privilege || ' WITH GRANT OPTION'
            )
        FROM relations, unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS held_privilege
        WHERE relations.relkind = 'S'
            AND has_sequence_privilege(runtime_oid, relations.oid, held_privilege)
        UNION ALL
        SELECT 'function', function_row.oid::text, '', 'EXECUTE',
            has_function_privilege(runtime_oid, function_row.oid, 'EXECUTE WITH GRANT OPTION')
        FROM pg_proc AS function_row
        WHERE function_row.pronamespace = schema_oid
            AND has_function_privilege(runtime_oid, function_row.oid, 'EXECUTE')
    ),
    expected(kind, object, column_name, privilege) AS (
        SELECT 'schema', '', '', privilege FROM matrix WHERE kind = 'schema'
        UNION
        SELECT 'table', relation, '', privilege FROM matrix WHERE kind = 'table'
        UNION
        SELECT 'column', matrix.relation, live_columns.column_name, matrix.privilege
        FROM matrix
        JOIN live_columns ON live_columns.name = matrix.relation
        WHERE (matrix.kind = 'table'
                AND matrix.privilege IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES'))
            OR (matrix.kind = 'columns except'
                AND live_columns.column_name <> ALL (string_to_array(matrix.column_rule, ',')))
            OR (matrix.kind = 'columns only'
                AND live_columns.column_name = ANY (string_to_array(matrix.column_rule, ',')))
    )
    SELECT
        (SELECT count(*) FROM (
            SELECT kind, object, column_name, privilege FROM held
            EXCEPT SELECT kind, object, column_name, privilege FROM expected
        ) AS extra)
        + (SELECT count(*) FROM (
            SELECT kind, object, column_name, privilege FROM expected
            EXCEPT SELECT kind, object, column_name, privilege FROM held
        ) AS missing)
        + (SELECT count(*) FROM held WHERE grantable)
    INTO differences;
    IF differences <> 0 THEN
        RAISE EXCEPTION 'the runtime role privileges differ from the runtime matrix'
            USING ERRCODE = '42501';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_trigger AS trigger_row
        JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid
        WHERE relation.relnamespace = schema_oid
            AND NOT trigger_row.tgisinternal AND trigger_row.tgenabled <> 'A'
    ) THEN
        RAISE EXCEPTION 'every trigger must fire in every session replication role'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE pronamespace = schema_oid
            AND proconfig IS DISTINCT FROM
                ARRAY[format('search_path=%s, pg_temp', quote_ident(current_schema()))]
    ) THEN
        RAISE EXCEPTION 'every function must pin its search path' USING ERRCODE = '55000';
    END IF;
END;
$postcondition$;
