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
| `DOCCHAIN_DATABASE__USER` | `docchain` |
| `DOCCHAIN_DATABASE__PASSWORD` | Read from the password file when unset |
| `DOCCHAIN_DATABASE__PASSWORD_FILE` | Required when `DOCCHAIN_DATABASE__PASSWORD` is unset |
| `DOCCHAIN_DATABASE__MAX_CONNECTIONS` | `10` (accepted range 2 to 64) |
| `DOCCHAIN_DATABASE__SCHEMA` | `public` (an existing schema; lower-case PostgreSQL identifier) |
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

To run the HTTP service after supplying every required path above, use `cargo run -p docchain-server`.
It applies its embedded migrations before accepting requests. Standard input is ignored. SIGINT or
SIGTERM stops intake and drains admitted requests; a complete drain exits zero, while exceeding the
configured shutdown deadline cancels the remaining requests, which receive `503` with the category
`dependency-failure` if their connection is still open, and exits nonzero. A cancelled send retried
with the same idempotency key returns the prior result if it had committed. Startup fails before
migrating when the connection's current schema is not `DOCCHAIN_DATABASE__SCHEMA`. Each exchange
records when its send checked its keys; a schema that already holds exchanges or events stored
without that time is refused by the migration, and startup stops, because no true value exists for
them.

`GET /health/live` answers `204` while the process runs. `GET /health/ready` answers `204` only when
PostgreSQL responds and the document-store root was proven writable within the last second, and
`503` with an empty body otherwise. At most one writability probe runs at a time, and its result
answers every readiness check for one second.

Every API request carries `Authorization: Bearer <credential>`, verified against the configured
credential file; no other header selects a wallet or role.

`GET /v1/audit/verify` returns the server-verified signed chain head. An auditor who presents a head
it verified earlier, as `head_sequence`, `head_event_hash`, and `head_signature` query parameters,
is told when events after it have gone. A first call establishes a baseline only, because the
service that answers holds the audit key. A chain longer than 100,000 events returns `503` with the
category `audit-incomplete` rather than a verdict for part of it. Accepting an exchange returns only
that exchange's ID and `credit_awarded: 1`. Reading a document checks the sender's and reader's keys
as they stood when the copy was sent, so a key revocation that takes effect later leaves earlier
copies readable.

The command reproduces the byte-exact version 1 envelope vector, then runs the system tests one at a
time. Together they cover delivery, acceptance, replay protection, schema rejection, privacy,
integrity, and independent audit. Each test creates its own database schema and temporary
document-store root under `TMPDIR`, reads the database coordinates from the `DOCCHAIN_DATABASE__*`
variables or, failing those, from `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD_FILE`, and
never starts, stops, resets, or deletes the PostgreSQL service.

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
