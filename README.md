# Docchain

Docchain demonstrates private exchange of immutable, schema-approved JSON documents between synthetic
citizen and institution wallets, with verifiable history and non-monetary demonstration credits.

It is a pre-release, local proof of concept that uses invented data only. It makes no production,
legal-effect, or privileged-host secrecy claim.

## Prerequisites

| Tool | Needed | Without it |
|---|---|---|
| Git and [`rustup`](https://rustup.rs) | Required | Nothing builds. `rustup` installs the toolchain pinned in `rust-toolchain.toml` |
| PostgreSQL | Required to run the demonstration and the system tests | Building and the unit tests still work |
| [`just`](https://github.com/casey/just) | Optional | Run the commands listed in [CONTRIBUTING.md](CONTRIBUTING.md#commands) |
| `cargo-nextest` | Optional | `just test` falls back to `cargo test` |
| `cargo-deny` | Optional locally, required in CI | `just deny` reports that it skipped |

SQLite is not a substitute for PostgreSQL.

## Build

```bash
just bootstrap     # check the tools and install the pinned toolchain
just check-fast    # formatting, compilation, and unit tests
```

Without `just`, the equivalent is:

```bash
rustup toolchain install --no-self-update
cargo build --workspace
cargo test --workspace --lib
```

Run `just check` before proposing a change. [CONTRIBUTING.md](CONTRIBUTING.md) lists every recipe.

## Run the demonstration

The server reads typed `DOCCHAIN_` settings once at startup. Key, credential, and database password
values are supplied as mounted files. The settings are:

| Variable | Default |
|---|---|
| `DOCCHAIN_DATABASE__HOST` | `postgres` |
| `DOCCHAIN_DATABASE__PORT` | `5432` |
| `DOCCHAIN_DATABASE__NAME` | `docchain` |
| `DOCCHAIN_DATABASE__USER` | `docchain`. Set it to the runtime role the platform provisioned; the default is only a name, not that role. `docchain-migrate` requires it explicitly, as a lower-case PostgreSQL identifier other than the owner |
| `DOCCHAIN_DATABASE__PASSWORD` | Read from the password file when unset; the server only |
| `DOCCHAIN_DATABASE__PASSWORD_FILE` | Required when `DOCCHAIN_DATABASE__PASSWORD` is unset; the server only |
| `DOCCHAIN_DATABASE__MAX_CONNECTIONS` | `10` (accepted range 2 to 64) |
| `DOCCHAIN_DATABASE__SCHEMA` | Required, no default: an existing schema the migration owner owns, a lower-case PostgreSQL identifier, never `public` |
| `DOCCHAIN_MIGRATION__USER` | Required by `docchain-migrate` only: the migration owner. The server refuses to start when any `DOCCHAIN_MIGRATION__` variable is set |
| `DOCCHAIN_MIGRATION__PASSWORD` or `DOCCHAIN_MIGRATION__PASSWORD_FILE` | Required by `docchain-migrate` only, with the same rules as the runtime password |
| `DOCCHAIN_HTTP__BIND` | `127.0.0.1:3000` |
| `DOCCHAIN_HTTP__REQUEST_TIMEOUT_MS` | `5000` (accepted range 1 to 60000) |
| `DOCCHAIN_HTTP__MAX_IN_FLIGHT` | `64` (accepted range 1 to 1024) |
| `DOCCHAIN_HTTP__SHUTDOWN_TIMEOUT_MS` | `10000` (accepted range 1 to 60000) |
| `DOCCHAIN_DOCUMENT_STORE__ROOT` | Required absolute, non-root path |
| `DOCCHAIN_IDENTITY__CREDENTIALS_FILE` | Required synthetic-identity credential file |
| `DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE` | Required registry-authority public-key file |
| `DOCCHAIN_KEYS__BINDINGS_FILE` | Required signed key-binding registry file |
| `DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES` | Required comma-separated wallet signing-key files |
| `DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES` | Required comma-separated wallet encryption-key files |
| `DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE` | Required audit signing-key file |
| `DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT` | Required canonical base64url SHA-256 fingerprint, provisioned separately |
| `DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS` | `100000` (accepted range 1 to 100000) |
| `DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE` | `100` (accepted range 1 to 500) |
| `DOCCHAIN_DIAGNOSTICS__SPANS` | `on`; `off` stops the request and use-case records only. Any other value stops startup |

A missing or malformed setting stops startup with a message that names the variable but never its
value. `PGOPTIONS` is refused so it cannot override the configured schema. PostgreSQL TLS variables
are ignored because this local profile explicitly disables TLS. Supply the password at runtime, and
never commit it. Then run:

```bash
just demo-first-slice
```

To run the HTTP service, first bring the schema up to date with `just migrate` (see
[Database roles](#database-roles)), then, after supplying every required path above, use
`cargo run -p docchain-server`. The server never applies migrations. Before it listens, it checks, in
order, that the schema exists, that every embedded migration is applied unchanged, that the
connection's schema is `DOCCHAIN_DATABASE__SCHEMA`, and that its role holds exactly the runtime
privileges below; otherwise it exits nonzero with one of `database connection` (it cannot connect,
or a query of a startup check fails), `database schema`, `database migrations pending`,
`database migrations mismatch`, or `database role privileges`, and never names a user, password,
path, or which privilege failed. `database migrations pending` means that an embedded migration is
not yet applied, or that the server's role cannot use the schema or read the migration ledger, as
when `DOCCHAIN_DATABASE__USER` names a role the migrations did not grant, which `just migrate` alone
does not fix; a failed query of the migration state reports `database connection`.
It then loads its key and identity files, takes the document-store lease, and runs the startup
sweep described in [Document store root](#document-store-root). Standard input is ignored. SIGINT or
SIGTERM stops intake and drains admitted requests; a complete drain exits zero, while exceeding the
configured shutdown deadline cancels the remaining requests, which receive `503` with the category
`dependency-failure` if their connection is still open, and exits nonzero. A cancelled send retried
with the same idempotency key returns the prior result if it had committed. Each exchange records
when its send checked its keys; a schema that already holds exchanges or events stored without that
time is refused by the migration, because no true value exists for them.

`GET /health/live` answers `204` while the process runs. `GET /health/ready` answers `204` only when
PostgreSQL responds and the document-store root was proven writable within the last second, and
`503` with an empty body otherwise. At most one writability probe runs at a time, and its result
answers every readiness check for one second.

### Diagnostics

The server writes diagnostic records to standard output, one JSON object per line, and nothing else
there. Standard error keeps only its human-readable lines. Every record field is a fixed word or an
integer; no record holds a path, query, header, body, identifier, key, secret, or free text, and the
server installs no logger, so dependency messages such as SQL text are never printed. Records carry no
timestamp: the collector that reads standard output stamps each line.

- `{"record":"request","request_id":1,"operation":"send-copy","outcome":"ok","duration_us":1234}`,
  one per HTTP request, and `{"record":"use-case",...}` with the same fields, one per application call
  that request makes. `request_id` is a sequence number that restarts at 1 with each process; it never
  comes from the request, is never returned to the client, and `X-Request-Id` or `traceparent` is
  ignored. `operation` is `send-copy`, `accept`, `read-document`, `list-inbox`, `verify-audit`,
  `audit-key`, `export-audit-events`, `live`, `ready`, `read-counters`, or `unmatched`. `outcome` is
  `ok`, `cancelled`, the response's error category (for example `forbidden` or `replay`), `not-ready`,
  or, when a response has no category, `not-found`, `method-not-allowed`, `payload-too-large`,
  `rejected`, or `server-error`.
- `{"record":"startup-failed","step":"audit key file"}`, once, when startup fails before the listener
  binds, next to the unchanged standard-error line. A configuration failure adds `setting` and
  `reason`, for example `"setting":"DOCCHAIN_DATABASE__PORT","reason":"has an invalid value"`; a
  setting or reason outside the fixed list is reported as `DOCCHAIN_*` and `is invalid`.

Records are best-effort and are not an audit trail. They pass through a queue of 4,096 records to one
writer thread, a full queue drops a record instead of delaying a request, and the process waits at
most one second at exit for queued records. A write that standard output refuses, in whole or in
part, loses that record, and it is never retried. Records hold no identifier, but a reader who also
holds the event chain can link them to activity by the collector's timestamps, so treat standard
output as pseudonymous activity metadata.

`GET /operations/counters` returns exact per-process counts for the operator credential only, behind
the same admission limit and deadline as the API, with `Cache-Control: no-store`:

```json
{"version":1,"counters":[{"operation":"send-copy","outcome":"ok","count":2}],"dropped_records":0}
```

`counters` lists only nonzero operation and outcome pairs; `dropped_records` counts records lost from
the queue or refused by standard output, for example once the collector's pipe closes. Records still
queued when the exit flush ends are not counted. Counts restart at zero with the process, and a read
does not count itself. A missing or unknown credential gets `401`, any other role `403`, and a query
or a body `422`.

Every API request carries `Authorization: Bearer <credential>`, verified against the configured
credential file; no other header selects a wallet or role.

`GET /v1/audit/verify` returns the server-verified signed chain head. An auditor who presents a head
it verified earlier, as `head_sequence`, `head_event_hash`, and `head_signature` query parameters,
is told when events after it have gone. A first call establishes a baseline only, because the
service that answers holds the audit key. The chain tail and the whole credit ledger are read in one
snapshot, and a successful body carries `credits`: `{"reconciled": true, "accepted_exchanges": N,
"credit_transactions": N}`, stating that every accepted exchange has exactly one balanced credit
transaction and every credit transaction belongs to exactly one accepted exchange. A failure is
`409` with exactly `{"category": "integrity-failure", "reason": <code>}`, where the code names the
first failing class, checked in this order: `event-chain`, `envelope-commitment`,
`credit-unaccepted`, `credit-duplicate`, `credit-unbalanced`, `credit-missing`. Neither response
carries an exchange, wallet, key, or amount per wallet. A chain longer than 100,000 events, or a
ledger longer than 100,000 transactions or 200,000 entries, returns `503` with the category
`audit-incomplete` rather than a verdict for part of it. Accepting an exchange returns only
that exchange's ID and `credit_awarded: 1`. Reading a document checks the sender's and reader's keys
as they stood when the copy was sent, so a key revocation that takes effect later leaves earlier
copies readable.

The command reproduces the byte-exact version 1 envelope vector, then runs the system tests one at a
time. Together they cover delivery, acceptance, replay protection, schema rejection, privacy,
integrity, independent audit, and the database role checks. Each test creates its own database
schema and temporary document-store root under `TMPDIR`. It reads the runtime role's credential from
the `DOCCHAIN_DATABASE__*` variables and the migration owner's from the `DOCCHAIN_MIGRATION__*`
variables that the recipe sets; a missing variable fails the test and names it. The owner creates,
migrates, inspects, and drops each schema, and the service under test uses only the runtime role.
Tests refuse a superuser for either role, never create or alter roles, and never start, stop,
reset, or delete the PostgreSQL service.

### Document store root

The server owns three names in `DOCCHAIN_DOCUMENT_STORE__ROOT`: `.docchain-lock`, `.docchain-binding`,
and, briefly, `.docchain-binding.tmp`. Each is created with mode `0600`, never through a symlink, and
a control file that is a symlink, is not a regular file, or has group or other permission bits stops
startup.

- **Lease.** Every running server holds a shared lock on its schema, through one extra PostgreSQL
  connection outside its pool, and a shared `flock` on `.docchain-lock`, until it exits. Only a start
  that obtains both locks exclusively may remove anything. Every server that uses a root must be a
  current build that holds this lease; an older build does not take it and is not excluded. Sharing a
  root across hosts is unsupported.
- **Binding.** `.docchain-binding` ties the root to one schema of one PostgreSQL cluster and
  database. The server writes it once, only into a root that holds no object or temporary names, and
  never rewrites it. A root bound to another schema, or a binding that is unreadable or malformed,
  stops startup at `document store binding`, before anything is written: point the server at the
  right schema, or empty the root with a reset that validates its target. Copying a binding into
  another root declares that root to belong to that schema. An unbound root that already holds
  objects is never swept.
- **Startup sweep.** Before it listens, an exclusive start waits up to 10 seconds for transactions
  already open on the schema to end, lists the root (at most 100,000 entries), and reads every stored
  object reference in one snapshot. It then removes each object file that no stored reference names
  and each `.<object>.tmp` file an interrupted write left. Symlinks, directories, special files, and
  other names are never followed or removed. An object copied into a bound root is removed at the
  next exclusive start unless a stored reference names it.
- **Report.** The server writes one line to standard error before it listens:
  `docchain-server: document store sweep: removed <n> objects and <n> temporary files; kept <n> referenced objects; skipped <n> entries`,
  or `docchain-server: document store sweep skipped: <reason>`, where the reason is
  `exclusivity not obtained` (another server holds the schema or root), `store root not bound`,
  `earlier transactions still open`, or `inventory over bound`. A skipped sweep removes nothing, and
  the server still starts. No line names an object, a path, or a database identifier. If the line
  cannot be written, it is lost and the server still starts.
- **Failures.** When the stored references cannot all be read, the server removes nothing and exits
  nonzero with `document store references`. The other startup failures of this step are
  `document store root`, `document store exclusivity` (the locks or the lease connection failed, or
  shared locks were not obtained within 10 seconds), `document store inventory`, and
  `document store sweep`. Row-level security enabled on `exchanges` or `audit_events` also fails at
  `document store references`; the migration owner recovers by disabling row-level security.

### Database roles

Docchain uses two PostgreSQL roles. The platform provisions and names both; Docchain applies no
role name of its own. `docchain-migrate` connects as `DOCCHAIN_MIGRATION__USER`, which has no
default. The server connects as `DOCCHAIN_DATABASE__USER`, which must name the runtime role.

- The **migration owner** owns the configured schema and every object in it. Only
  `docchain-migrate` connects as it. It must not be a superuser: `docchain-migrate` and the tests
  refuse a superuser session. For the tests' disposable schemas it needs CREATE on the database; it
  does not need CREATEROLE.
- The **runtime role** is the only role the server uses. It has LOGIN and CONNECT, no superuser,
  CREATEROLE, CREATEDB, REPLICATION, or BYPASSRLS attribute, membership in no role, ownership of
  nothing, no parameter privilege, no CREATE on the database, and no per-role setting. The schema
  migrations grant it exactly: USAGE on the schema; SELECT on `exchanges`, INSERT on every
  `exchanges` column except `accepted`, and UPDATE on `accepted` only; SELECT and INSERT on
  `audit_events`, `credit_transactions`, and `credit_entries`; INSERT on `acceptances`; SELECT on
  `_sqlx_migrations`; and nothing else, no sequence or function privilege and no grant option. It
  therefore cannot drop, disable, or bypass a trigger, alter, truncate, or rewrite a table, record a
  migration, or switch roles. An accepted exchange cannot be reset, and every trigger fires in every
  session replication role.

**Process environments.** Each process holds one database credential. The shared environment of
the container sets only the server's keys: `DOCCHAIN_DATABASE__USER` and
`DOCCHAIN_DATABASE__PASSWORD_FILE` naming the runtime role and its file, and
`DOCCHAIN_DATABASE__SCHEMA` naming the project's schema. No `DOCCHAIN_MIGRATION__` variable belongs
there. `just migrate`, `just test`, and `just demo-first-slice` set the owner's keys on their own
commands only, from the `justfile` variables `migration_owner` and
`migration_owner_password_file`. Without `just`, for example:

```bash
DOCCHAIN_MIGRATION__USER=docchain_owner \
DOCCHAIN_MIGRATION__PASSWORD_FILE=/run/secrets/docchain_owner_key \
    cargo run -p docchain-server --bin docchain-migrate
```

`docchain-migrate` takes no arguments and never reads standard input. It connects as the owner
(`database connection` when it cannot connect, or its schema query fails), refuses a superuser
session (`database owner role`), requires the schema to exist (`database schema`), and applies
every pending forward migration (`database migration`). It exits
0 when the schema is current, 1 on a failure, and 2 when given any argument. The migration that
grants the runtime role refuses to run unless the owner owns the schema and everything in it, the
schema is not `public`, and the runtime role meets the rules above; a schema created and migrated by
another role cannot be upgraded and is replaced by a fresh one, because its data is synthetic.

**Platform requirements.** These are outside Docchain:

- Create both roles without a `PASSWORD` clause, then set each password with psql's `\password`,
  which sends only a verifier computed by the client. The server logs the text of a failing
  statement, so a cleartext password must never appear in SQL. Supply each password as a mounted
  file.
- Once the roles and schema are provisioned, the application container holds no valid platform
  superuser credential. In the provisioning session, the platform sets a new superuser password that
  never enters the application container, ends every superuser session from the network, and removes
  the old password file and every variable that names it or carries a superuser password. Removal
  alone is not enough, because a copy read earlier survives it. No Docchain process needs the
  superuser.
- No database credential that has been readable in the local container is ever valid in any other
  environment. Every other environment gets its own passwords, set there with client-computed
  verifiers. In the local container the server's operating-system identity can also read the
  owner's password file; that is accepted there only for a limited time, after which the platform
  separates the owner file and sets a new owner password that identity has never been able to read.
- Outside the local container, the identity that runs the server can read only the runtime role's
  password file and the key and identity files the server's own settings name. The owner's password
  file is mounted only for the migrator's run.
- Revoking TEMPORARY on the database from PUBLIC is recommended but not required.

**Recovery after a leaked runtime credential.** Its holder can leave an owned object, a per-role
setting, or a changed password behind; the server then refuses to start (`database role
privileges`) or cannot connect (`database connection`). Neither the server nor the owner can undo
that; the platform, as the superuser, does:

1. Set a new runtime password with psql's `\password`, and replace the runtime password file.
2. End every remaining session of the runtime role.
3. In each database where `pg_shdepend` records an object the runtime role owns, run
   `REASSIGN OWNED BY <runtime role> TO <platform role>`. Never run `DROP OWNED BY` for the runtime
   role: it also revokes the role's grants, which only the migrations give.
4. Run `ALTER ROLE <runtime role> RESET ALL`, and the same with `IN DATABASE <database>` for each
   database that has a setting for it.
5. Start the server; its startup checks confirm the recovery.
6. Run audit verification. If it fails, replace the synthetic schema.

If the leak may have come from inside the container, change the owner password too.

### Independent audit

The audit fingerprint is the unpadded base64url encoding of the SHA-256 digest of the 32-byte
Ed25519 public key that belongs to the audit signing key. Before a demonstration, the product owner
approves that one value and hands it separately to the server operator, as
`DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT`, and to the auditor, as an input to the auditor's own
verifier. The server derives the fingerprint of its loaded key and refuses to start, before it binds
its listener, when the two differ. The auditor never learns the expected value from the service and
never trusts a fingerprint on first use.

Only the auditor credential is served by these operations; any other credential receives `403
forbidden`. Every response from them, success or error, carries `Cache-Control: no-store`, and all
proof travels in response and request bodies, never the request target.

- `GET /v1/audit/key` takes no query and no body and returns exactly `public_key` and
  `fingerprint`, both unpadded base64url. The auditor checks both against its separately provisioned
  fingerprint.
- `POST /v1/audit/events/export` takes no query and a JSON body of at most 4 KiB and depth four.
  The first request is `{"challenge": <32 fresh random bytes the auditor generated and keeps>,
  "limit": <optional, 1 to 500>}`. The service selects the current chain snapshot and returns a
  `manifest` (`export_version`, `challenge`, `audit_key_fingerprint`, `event_count`, and the signed
  `head`, or `null` for an empty chain), the audit key's `manifest_signature` over it, `coverage`,
  up to `limit` `events`, and `next_after_sequence`. Each event holds `preimage_version` `1`, the
  exact `preimage` bytes its `event_hash` digests, `sequence`, `previous_event_hash`, `event_hash`,
  and `signature`. To continue, send `{"manifest", "manifest_signature", "after_sequence", "limit"}`
  with the manifest and signature unchanged and `after_sequence` set to the previous
  `next_after_sequence`. Every page repeats the same manifest; events appended after the first
  page are not part of the export. Only the page that ends at `event_count` says
  `coverage: "complete"` with `next_after_sequence: null`; every earlier page says `"partial"`.
- An unknown, duplicated, malformed, or out-of-bound request member returns `422 invalid-request`,
  including a manifest this key did not sign. A snapshot that changed underneath a continuation
  returns `409 integrity-failure`. A chain longer than `DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS` returns
  `503 audit-incomplete` with no page.

The auditor verifies offline, from those bytes, its own challenge, and its provisioned fingerprint:
the manifest signature and challenge, the unchanged manifest on every page, contiguous sequences from
1, each preimage's hash, embedded sequence and previous hash, and each event signature, and that the
final page reaches the signed head. The first complete export is a baseline only. A later export
detects rollback at or before the newest checkpoint the auditor retained from an earlier verified
export. Neither proves absolute freshness, nor that the key holder showed every auditor the same
snapshot.

## Layout

| Path | Holds |
|---|---|
| `crates/docchain-domain` | Types, strict JSON validation and canonicalization, and event integrity |
| `crates/docchain-application` | Commands, authorization, and ports |
| `apps/docchain-server` | Composition root and the HTTP, PostgreSQL, document-store, and cryptographic adapters |
| `apps/docchain-server/migrations` | The database schema |
| `schemas/service-application` | The approved document schema and its invented example |
| `tests/system` | System tests of the complete exchange |
| `tests/vectors` | The version 1 envelope conformance vector |

## Security and licence

Report vulnerabilities as described in [SECURITY.md](SECURITY.md). The source is proprietary; see
[LICENSE](LICENSE).
