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
| `DOCCHAIN_DATABASE__USER` | `docchain`; the runtime role. `docchain-migrate` requires it explicitly, as a lower-case PostgreSQL identifier other than the owner |
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
privileges below; otherwise it exits nonzero with one of `database schema`,
`database migrations pending`, `database migrations mismatch`, or `database role privileges`, and
never names a user, password, path, or which privilege failed. Standard input is ignored. SIGINT or
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

### Database roles

Docchain uses two PostgreSQL roles, which the platform provisions:

- The **migration owner** (`docchain_owner` by default) owns the configured schema and every object
  in it. Only `docchain-migrate` connects as it. It must not be a superuser: `docchain-migrate` and
  the tests refuse a superuser session. For the tests' disposable schemas it needs CREATE on the
  database; it does not need CREATEROLE.
- The **runtime role** (`docchain_runtime` by default) is the only role the server uses. It has LOGIN
  and CONNECT, no superuser, CREATEROLE, CREATEDB, REPLICATION, or BYPASSRLS attribute, membership
  in no role, ownership of nothing, no parameter privilege, no CREATE on the database, and no per-role
  setting. The schema migrations grant it exactly: USAGE on the schema; SELECT on `exchanges`, INSERT
  on every `exchanges` column except `accepted`, and UPDATE on `accepted` only; SELECT and INSERT on
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
`migration_owner_password_file`. Without `just`:

```bash
DOCCHAIN_MIGRATION__USER=docchain_owner \
DOCCHAIN_MIGRATION__PASSWORD_FILE=/run/secrets/docchain_owner_key \
    cargo run -p docchain-server --bin docchain-migrate
```

`docchain-migrate` takes no arguments and never reads standard input. It connects as the owner,
refuses a superuser session (`database owner role`), requires the schema to exist
(`database schema`), and applies every pending forward migration (`database migration`). It exits
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
