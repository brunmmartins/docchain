//! The server runs as a runtime role that holds exactly its privilege matrix, cannot weaken the
//! database's integrity controls, and never migrates. The migration owner inspects and tampers.
#![cfg(unix)]

mod support;

use std::{
    collections::BTreeSet,
    io::Read as _,
    net::SocketAddr,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use docchain_application::AuditExportRequest;
use docchain_domain::{AuditChallenge, IdempotencyKey};
use docchain_server::{DatabaseFixture, DemoHarness};
use sqlx::PgPool;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

/// Every table the migrations create, the migration ledger included.
const TABLES: [&str; 6] = [
    "exchanges",
    "audit_events",
    "acceptances",
    "credit_transactions",
    "credit_entries",
    "_sqlx_migrations",
];

/// The runtime privilege matrix, written out independently of the code that checks it:
/// table-level privileges, then column privileges beyond them.
const TABLE_PRIVILEGES: [(&str, &[&str]); 6] = [
    ("exchanges", &["SELECT"]),
    ("audit_events", &["SELECT", "INSERT"]),
    ("acceptances", &["INSERT"]),
    ("credit_transactions", &["SELECT", "INSERT"]),
    ("credit_entries", &["SELECT", "INSERT"]),
    ("_sqlx_migrations", &["SELECT"]),
];

/// One effective privilege: kind, object, column, privilege.
type Privilege = (String, String, String, String);

/// Every effective privilege the runtime role holds on the schema and its objects, with
/// whether it holds it with grant option, as the owner reads the catalogs.
async fn effective_privileges(owner: &PgPool, role: &str) -> Vec<(Privilege, bool)> {
    let rows: Vec<(String, String, String, String, bool)> = sqlx::query_as(
        "WITH role AS (SELECT oid FROM pg_roles WHERE rolname = $1), \
         namespace AS (SELECT oid FROM pg_namespace WHERE nspname = current_schema()), \
         relations AS (SELECT relation.oid, relation.relname::text AS name, relation.relkind \
             FROM pg_class AS relation, namespace \
             WHERE relation.relnamespace = namespace.oid \
                 AND relation.relkind IN ('r', 'v', 'm', 'f', 'p', 'S')) \
         SELECT 'schema', '', '', held, \
             has_schema_privilege(role.oid, namespace.oid, held || ' WITH GRANT OPTION') \
         FROM role, namespace, unnest(ARRAY['USAGE', 'CREATE']) AS held \
         WHERE has_schema_privilege(role.oid, namespace.oid, held) \
         UNION ALL \
         SELECT 'table', relations.name, '', held, \
             has_table_privilege(role.oid, relations.oid, held || ' WITH GRANT OPTION') \
         FROM role, relations, unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', \
             'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']) AS held \
         WHERE relations.relkind <> 'S' AND has_table_privilege(role.oid, relations.oid, held) \
         UNION ALL \
         SELECT 'column', relations.name, attribute.attname::text, held, \
             has_column_privilege(role.oid, relations.oid, attribute.attnum, \
                 held || ' WITH GRANT OPTION') \
         FROM role, relations \
         JOIN pg_attribute AS attribute ON attribute.attrelid = relations.oid \
             AND attribute.attnum > 0 AND NOT attribute.attisdropped, \
         unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS held \
         WHERE relations.relkind <> 'S' \
             AND has_column_privilege(role.oid, relations.oid, attribute.attnum, held) \
         UNION ALL \
         SELECT 'sequence', relations.name, '', held, FALSE \
         FROM role, relations, unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS held \
         WHERE relations.relkind = 'S' \
             AND has_sequence_privilege(role.oid, relations.oid, held) \
         UNION ALL \
         SELECT 'function', function_row.proname::text, '', 'EXECUTE', FALSE \
         FROM role, namespace, pg_proc AS function_row \
         WHERE function_row.pronamespace = namespace.oid \
             AND has_function_privilege(role.oid, function_row.oid, 'EXECUTE')",
    )
    .bind(role)
    .fetch_all(owner)
    .await
    .expect("effective privileges");
    rows.into_iter()
        .map(|(kind, object, column, privilege, grantable)| {
            ((kind, object, column, privilege), grantable)
        })
        .collect()
}

/// The effective privileges the matrix implies, given each table's live columns.
async fn expected_privileges(owner: &PgPool) -> BTreeSet<Privilege> {
    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema()",
    )
    .fetch_all(owner)
    .await
    .expect("columns");
    let text = |value: &str| value.to_owned();
    let mut expected = BTreeSet::from([(text("schema"), text(""), text(""), text("USAGE"))]);
    for (table, privileges) in TABLE_PRIVILEGES {
        for privilege in privileges {
            expected.insert((text("table"), text(table), text(""), text(privilege)));
            for (_, column) in columns.iter().filter(|(name, _)| name == table) {
                expected.insert((text("column"), text(table), column.clone(), text(privilege)));
            }
        }
    }
    for (_, column) in columns.iter().filter(|(name, _)| name == "exchanges") {
        if column == "accepted" {
            expected.insert((
                text("column"),
                text("exchanges"),
                text("accepted"),
                text("UPDATE"),
            ));
        } else {
            expected.insert((
                text("column"),
                text("exchanges"),
                column.clone(),
                text("INSERT"),
            ));
        }
    }
    expected
}

#[tokio::test]
async fn serves_journey_with_minimal_grants() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");

    // The complete journey, as the runtime role: send, inbox, read, accept, replay, verify,
    // key, and export.
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    assert_eq!(
        harness
            .list_inbox(&recipient, &support::wallet(support::RECIPIENT))
            .await
            .expect("inbox"),
        std::slice::from_ref(&delivered.exchange_id)
    );
    harness
        .read_document(&recipient, &delivered.exchange_id)
        .await
        .expect("read");
    let key = IdempotencyKey::new("idem_accept0000000001").expect("acceptance key");
    let accepted = harness
        .accept(&recipient, &delivered.exchange_id, &key)
        .await
        .expect("acceptance");
    let replayed_send = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("send replay");
    assert_eq!(replayed_send.exchange_id, delivered.exchange_id);
    assert_eq!(
        harness
            .accept(&recipient, &delivered.exchange_id, &key)
            .await
            .expect("acceptance replay"),
        accepted
    );
    let report = harness.verify_audit(None).await.expect("verified");
    assert_eq!(
        (
            report.event_count,
            report.credits.accepted_exchanges(),
            report.credits.credit_transactions()
        ),
        (2, 1, 1)
    );
    harness.audit_public_key().await.expect("audit key");
    let export = harness
        .export_audit_events(
            AuditExportRequest::start(AuditChallenge::new([7; 32]), None).expect("export"),
        )
        .await
        .expect("export page");
    assert_eq!(export.events.len(), 2);
    assert_eq!(
        harness
            .database()
            .runtime_privilege_violations()
            .await
            .expect("privilege check"),
        Vec::<String>::new()
    );

    // The owner's own catalog reads.
    let owner = harness.owner_pool();
    let role = harness.database().runtime_role().to_owned();
    let principal: (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT role.rolsuper, role.rolcreaterole, role.rolcreatedb, role.rolreplication, \
             role.rolbypassrls, \
             EXISTS(SELECT 1 FROM pg_auth_members WHERE member = role.oid), \
             EXISTS(SELECT 1 FROM pg_database \
                 WHERE datname = current_database() AND datdba = role.oid), \
             EXISTS(SELECT 1 FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass \
                 AND refobjid = role.oid AND deptype = 'o'), \
             EXISTS(SELECT 1 FROM pg_parameter_acl, aclexplode(paracl) AS entry \
                 WHERE entry.grantee IN (role.oid, 0)), \
             EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole = role.oid), \
             has_database_privilege(role.oid, current_database(), 'CREATE') \
                 OR has_schema_privilege(role.oid, current_schema(), 'CREATE') \
             FROM pg_roles AS role WHERE role.rolname = $1",
    )
    .bind(&role)
    .fetch_one(owner)
    .await
    .expect("role attributes");
    assert_eq!(
        principal,
        (
            false, false, false, false, false, false, false, false, false, false, false
        ),
        "superuser, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS, membership, database \
         owner, owned object, parameter privilege, per-role setting, CREATE"
    );
    let temporary: bool =
        sqlx::query_scalar("SELECT has_database_privilege($1, current_database(), 'TEMPORARY')")
            .bind(&role)
            .fetch_one(owner)
            .await
            .expect("temporary privilege");
    // Recorded, not asserted: PUBLIC holds TEMPORARY unless the platform revokes it, and the
    // pinned search paths neutralize temporary-table shadowing.
    println!("runtime role TEMPORARY on the database: {temporary}");

    let held = effective_privileges(owner, &role).await;
    assert!(held.iter().all(|(_, grantable)| !grantable), "{held:?}");
    let held = held
        .into_iter()
        .map(|(privilege, _)| privilege)
        .collect::<BTreeSet<_>>();
    let expected = expected_privileges(owner).await;
    assert_eq!(
        held.difference(&expected).collect::<Vec<_>>(),
        Vec::<&Privilege>::new(),
        "beyond the matrix"
    );
    assert_eq!(
        expected.difference(&held).collect::<Vec<_>>(),
        Vec::<&Privilege>::new(),
        "missing from the matrix"
    );

    let triggers: Vec<(String, String)> = sqlx::query_as(
        "SELECT trigger_row.tgname::text, trigger_row.tgenabled::text \
         FROM pg_trigger AS trigger_row \
         JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid \
         WHERE relation.relnamespace = current_schema()::regnamespace \
             AND NOT trigger_row.tgisinternal ORDER BY 1",
    )
    .fetch_all(owner)
    .await
    .expect("triggers");
    assert!(!triggers.is_empty());
    assert!(
        triggers.iter().all(|(_, enabled)| enabled == "A"),
        "{triggers:?}"
    );
    let functions: Vec<(String, Option<Vec<String>>)> = sqlx::query_as(
        "SELECT proname::text, proconfig FROM pg_proc \
         WHERE pronamespace = current_schema()::regnamespace ORDER BY 1",
    )
    .fetch_all(owner)
    .await
    .expect("functions");
    let pinned = vec![format!(
        "search_path={}, pg_temp",
        harness.database().schema()
    )];
    assert_eq!(functions.len(), 3);
    assert!(
        functions
            .iter()
            .all(|(_, config)| config.as_ref() == Some(&pinned)),
        "{functions:?}"
    );
}

/// Row counts of every table, as the owner reads them.
async fn row_counts(owner: &PgPool) -> Vec<i64> {
    let mut counts = Vec::new();
    for table in TABLES {
        counts.push(
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(owner)
                .await
                .expect("row count"),
        );
    }
    counts
}

#[tokio::test]
async fn runtime_role_cannot_weaken_integrity() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("verified recipient");
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    harness
        .accept(
            &recipient,
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");
    let mut second = support::valid_request();
    second.document_version = docchain_domain::DocumentVersion::new(2).expect("version");
    second.request_nonce = docchain_domain::RequestNonce::new([0x22; 16]);
    second.idempotency_key = IdempotencyKey::new("idem_0000000000000002").expect("key");
    let pending = harness
        .send_copy(&sender, second)
        .await
        .expect("second delivery")
        .exchange_id;

    let owner = harness.owner_pool();
    let schema = harness.database().schema().to_owned();
    let before = row_counts(owner).await;
    let triggers: Vec<(String, String)> = sqlx::query_as(
        "SELECT trigger_row.tgname::text, relation.relname::text \
         FROM pg_trigger AS trigger_row \
         JOIN pg_class AS relation ON relation.oid = trigger_row.tgrelid \
         WHERE relation.relnamespace = current_schema()::regnamespace \
             AND NOT trigger_row.tgisinternal ORDER BY 1",
    )
    .fetch_all(owner)
    .await
    .expect("triggers");
    assert_eq!(triggers.len(), 11);

    let mut refused = Vec::new();
    for (trigger, table) in &triggers {
        refused.push((format!("DROP TRIGGER {trigger} ON {table}"), "42501"));
        refused.push((
            format!("ALTER TABLE {table} DISABLE TRIGGER {trigger}"),
            "42501",
        ));
    }
    for table in TABLES {
        refused.push((
            format!("ALTER TABLE {table} ADD COLUMN extra BIGINT"),
            "42501",
        ));
        refused.push((format!("DROP TABLE {table}"), "42501"));
        refused.push((format!("TRUNCATE {table}"), "42501"));
    }
    for (table, column) in [
        ("audit_events", "registry_sequence"),
        ("acceptances", "exchange_id"),
        ("credit_transactions", "eligibility_key"),
        ("credit_entries", "amount"),
    ] {
        refused.push((format!("UPDATE {table} SET {column} = {column}"), "42501"));
        refused.push((format!("DELETE FROM {table}"), "42501"));
    }
    let owner_role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(owner)
        .await
        .expect("owner role");
    refused.extend([
        (
            "UPDATE exchanges SET sender_wallet = sender_wallet".to_owned(),
            "42501",
        ),
        (
            "UPDATE exchanges SET accepted = FALSE WHERE accepted".to_owned(),
            "23001",
        ),
        ("SET session_replication_role = replica".to_owned(), "42501"),
        (format!("SET ROLE {owner_role}"), "42501"),
        (format!("CREATE TABLE {schema}.extra (id BIGINT)"), "42501"),
        (
            format!("CREATE FUNCTION {schema}.extra() RETURNS BIGINT LANGUAGE sql AS 'SELECT 1'"),
            "42501",
        ),
        (
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, \
             execution_time) VALUES (99, 'forged', TRUE, '\\x00', 0)"
                .to_owned(),
            "42501",
        ),
        (
            "UPDATE _sqlx_migrations SET success = FALSE".to_owned(),
            "42501",
        ),
        ("DELETE FROM _sqlx_migrations".to_owned(), "42501"),
    ]);
    for (statement, sqlstate) in &refused {
        // Rolled back on every path, so nothing the runtime role does here persists.
        assert_eq!(
            harness.sqlstate_as_runtime(statement, false).await,
            Err((*sqlstate).to_owned()),
            "{statement}"
        );
    }

    // A temporary table shadowing the ledger does not hide an unbalanced credit from the
    // balance trigger: COMMIT is refused. The table is dropped at commit in any case.
    let shadow = format!(
        "CREATE TEMPORARY TABLE credit_entries \
             (eligibility_key TEXT, account_id TEXT, amount BIGINT) ON COMMIT DROP; \
         INSERT INTO pg_temp.credit_entries VALUES \
             ('acceptance:{pending}', 'issuance', -1), ('acceptance:{pending}', '{sender}', 1); \
         INSERT INTO {schema}.credit_transactions VALUES ('acceptance:{pending}', '{pending}'); \
         INSERT INTO {schema}.credit_entries VALUES ('acceptance:{pending}', '{sender}', 1)",
        sender = support::SENDER,
    );
    assert_eq!(
        harness.sqlstate_as_runtime(&shadow, true).await,
        Err("23514".to_owned())
    );

    assert_eq!(row_counts(owner).await, before);
    assert!(harness.verify_audit(None).await.is_ok());
}

/// The status of `GET /health/ready`, or `None` when nothing answers.
async fn ready(address: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    stream
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    std::str::from_utf8(response.get(9..12)?).ok()?.parse().ok()
}

fn free_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    listener.local_addr().expect("free port address")
}

/// Runs `binary` with exactly `environment`, null standard input, and captured output.
fn spawn(binary: &str, environment: &[(String, String)]) -> Child {
    Command::new(binary)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary")
}

/// Waits up to thirty seconds for the process to exit; returns its status and output. The
/// process must not have become ready at `address` meanwhile.
async fn exit_before_ready(mut child: Child, address: Option<SocketAddr>) -> (ExitStatus, String) {
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("process status") {
            break status;
        }
        if let Some(address) = address {
            assert_ne!(ready(address).await, Some(204), "ready before exiting");
        }
        if started.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            panic!("process did not exit");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut output = String::new();
    for pipe in [
        child.stdout.take().map(|mut pipe| {
            let mut text = String::new();
            pipe.read_to_string(&mut text).expect("stdout");
            text
        }),
        child.stderr.take().map(|mut pipe| {
            let mut text = String::new();
            pipe.read_to_string(&mut text).expect("stderr");
            text
        }),
    ]
    .into_iter()
    .flatten()
    {
        output.push_str(&pipe);
    }
    (status, output)
}

/// The server's environment on a free loopback port, and that port.
fn server_environment(database: &DatabaseFixture) -> (Vec<(String, String)>, SocketAddr) {
    let address = free_address();
    let mut environment = database.server_environment();
    environment.push(("DOCCHAIN_HTTP__BIND".to_owned(), address.to_string()));
    (environment, address)
}

/// Starts the server, expects it to exit 1 before readiness, and returns its output.
async fn refused_start(environment: &[(String, String)], address: SocketAddr) -> String {
    let server = spawn(env!("CARGO_BIN_EXE_docchain-server"), environment);
    let (status, output) = exit_before_ready(server, Some(address)).await;
    assert_eq!(status.code(), Some(1), "{output}");
    output
}

/// Starts the server, waits for readiness, then stops it.
async fn serves(environment: &[(String, String)], address: SocketAddr) {
    let mut server = spawn(env!("CARGO_BIN_EXE_docchain-server"), environment);
    let started = Instant::now();
    while ready(address).await != Some(204) {
        if let Ok(Some(status)) = server.try_wait() {
            panic!("server exited before ready: {status}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "server not ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = server.kill();
    let _ = server.wait();
}

/// Whether `output` holds the value of any password file the environments name.
fn reveals_a_password(output: &str, environments: &[&[(String, String)]]) -> bool {
    environments
        .iter()
        .flat_map(|environment| environment.iter())
        .filter(|(key, _)| key.ends_with("__PASSWORD_FILE"))
        .filter_map(|(_, path)| std::fs::read_to_string(path).ok())
        .map(|password| password.trim().to_owned())
        .filter(|password| !password.is_empty())
        .any(|password| output.contains(&password))
}

async fn relation_count(owner: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_class WHERE relnamespace = current_schema()::regnamespace",
    )
    .fetch_one(owner)
    .await
    .expect("relations")
}

async fn ledger(owner: &PgPool) -> Vec<(i64, bool, Vec<u8>)> {
    sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(owner)
        .await
        .expect("migration ledger")
}

#[tokio::test]
async fn runtime_role_does_not_migrate() {
    let mut outputs = Vec::new();
    let database = DatabaseFixture::new()
        .await
        .expect("supplied PostgreSQL and a writable temporary root");
    let owner = database.owner_pool();
    let migration_environment = database.migration_environment();

    // (1) A fresh schema: the server refuses before readiness and creates nothing.
    let (environment, address) = server_environment(&database);
    let output = refused_start(&environment, address).await;
    assert!(
        output.trim_end().ends_with("database migrations pending"),
        "{output}"
    );
    assert_eq!(relation_count(owner).await, 0);
    outputs.push(output);

    // (2) A migration owner key in the server's environment is refused, naming the key.
    let (mut with_owner_key, address) = server_environment(&database);
    with_owner_key.extend(
        migration_environment
            .iter()
            .filter(|(key, _)| key.starts_with("DOCCHAIN_MIGRATION__"))
            .cloned(),
    );
    let output = refused_start(&with_owner_key, address).await;
    assert!(output.contains("DOCCHAIN_MIGRATION__"), "{output}");
    outputs.push(output);

    // (4) The migrator, with the owner's environment, brings the schema up to date; the
    // server then becomes ready.
    let migrator = spawn(
        env!("CARGO_BIN_EXE_docchain-migrate"),
        &migration_environment,
    );
    let (status, output) = exit_before_ready(migrator, None).await;
    assert_eq!(status.code(), Some(0), "{output}");
    outputs.push(output);
    let (environment, address) = server_environment(&database);
    serves(&environment, address).await;
    let migrated = ledger(owner).await;
    assert_eq!(migrated.len(), 6);

    // The migrator refuses any argument without connecting.
    let mut with_argument = Command::new(env!("CARGO_BIN_EXE_docchain-migrate"))
        .env_clear()
        .envs(migration_environment.iter().cloned())
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("migrator");
    let status = with_argument.wait().expect("migrator status");
    assert_eq!(status.code(), Some(2));

    // (5) One table privilege beyond the matrix, and (6) one column privilege beyond it,
    // each make the server refuse before readiness.
    let role = database.runtime_role().to_owned();
    for (granted, revoked) in [
        (
            format!("GRANT DELETE ON audit_events TO {role}"),
            format!("REVOKE DELETE ON audit_events FROM {role}"),
        ),
        (
            format!("GRANT UPDATE (sender_wallet) ON exchanges TO {role}"),
            format!("REVOKE UPDATE (sender_wallet) ON exchanges FROM {role}"),
        ),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(granted.clone()))
            .execute(owner)
            .await
            .expect("grant");
        let (environment, address) = server_environment(&database);
        let output = refused_start(&environment, address).await;
        assert!(
            output.trim_end().ends_with("database role privileges"),
            "{granted}: {output}"
        );
        outputs.push(output);
        sqlx::raw_sql(sqlx::AssertSqlSafe(revoked))
            .execute(owner)
            .await
            .expect("revoke");
    }
    let (environment, address) = server_environment(&database);
    serves(&environment, address).await;

    // (3) With the newest ledger row removed, the schema is pending again, and the server
    // leaves the ledger as it found it.
    sqlx::query(
        "DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)",
    )
    .execute(owner)
    .await
    .expect("remove the newest ledger row");
    let before = ledger(owner).await;
    assert_eq!(before.len(), 5);
    let (environment, address) = server_environment(&database);
    let output = refused_start(&environment, address).await;
    assert!(
        output.trim_end().ends_with("database migrations pending"),
        "{output}"
    );
    outputs.push(output);
    assert_eq!(ledger(owner).await, before);

    // No run printed either role's password.
    let server_environment = database.server_environment();
    for output in &outputs {
        assert!(!reveals_a_password(
            output,
            &[&server_environment, &migration_environment]
        ));
    }
}

/// A harness is also a migrated database: its server environment starts a ready server.
#[tokio::test]
async fn harness_schema_serves_with_the_runtime_role_only() {
    let harness: DemoHarness = support::harness().await;
    assert!(
        harness
            .server_environment()
            .iter()
            .all(|(key, _)| !key.starts_with("DOCCHAIN_MIGRATION__"))
    );
    let (environment, address) = server_environment(harness.database());
    serves(&environment, address).await;
}
