//! In-process mock identity, schema, key-registry, clock, and audit-key adapters.

use std::{collections::HashMap, fs, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use docchain_application::{
    Actor, Clock, Credential, EventIntegrity, Identity, IdentityError, IntegrityError, KeyPurpose,
    KeyRegistry, KeyRegistryError, SchemaArtifact, SchemaRegistry, SchemaRegistryError,
    VerifiedBinding,
};
use docchain_domain::{Timestamp, WalletId, canonicalize, parse_bounded_json, sha256};
use ed25519_consensus::{SigningKey, VerificationKey};
use serde::Deserialize;

use crate::{
    config::KeySettings,
    crypto::{strict_verify, valid_ed25519_public},
};

const MAX_PROVIDER_FILE: usize = 128 * 1024;
const BINDING_LABEL: &[u8] = b"docchain/key-binding/v1\0";

/// SHA-256 of the RFC 8785 form of the approved `service-application` 1.0.0 schema.
///
/// It is fixed at approval time and never recomputed from the served bytes, so a changed artifact
/// cannot approve itself.
pub(crate) const APPROVED_SERVICE_APPLICATION_DIGEST: [u8; 32] = [
    0x47, 0x9b, 0x5c, 0x72, 0x08, 0x46, 0xc0, 0xc0, 0x5e, 0xa5, 0xea, 0x73, 0xce, 0x19, 0xbb, 0x64,
    0xfc, 0x2b, 0x29, 0xda, 0xa9, 0x95, 0x99, 0xf6, 0xb8, 0x2d, 0x7c, 0xf5, 0xf6, 0x98, 0xbd, 0x86,
];

const SERVICE_APPLICATION_SCHEMA: &[u8] =
    include_bytes!("../../../schemas/service-application/1.0.0.schema.json");

/// Loads approved schema bytes embedded in this first-slice binary.
#[derive(Clone, Copy, Debug)]
pub struct StaticSchemaRegistry;

impl SchemaRegistry for StaticSchemaRegistry {
    async fn load_active(
        &self,
        schema_id: &str,
        version: &str,
    ) -> Result<SchemaArtifact, SchemaRegistryError> {
        if schema_id != "urn:docchain:schema:service-application:1.0.0" || version != "1.0.0" {
            return Err(SchemaRegistryError::NotFound);
        }
        Ok(SchemaArtifact {
            id: schema_id.to_owned(),
            version: version.to_owned(),
            approved_digest: APPROVED_SERVICE_APPLICATION_DIGEST,
            bytes: SERVICE_APPLICATION_SCHEMA.to_vec(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    wallets: HashMap<String, String>,
    auditor: String,
    operator: String,
}

/// Credential verifier backed by one configured secret file.
pub struct FileIdentity {
    wallets: Vec<(WalletId, Vec<u8>)>,
    auditor: Vec<u8>,
    operator: Vec<u8>,
}

impl FileIdentity {
    /// Loads and validates the mock identity file.
    pub fn load(path: &std::path::Path) -> Result<Self, IdentityError> {
        let bytes = fs::read(path).map_err(|_| IdentityError::Permanent)?;
        let parsed = parse_bounded_json(&bytes, MAX_PROVIDER_FILE, 8)
            .map_err(|_| IdentityError::Permanent)?;
        let file: IdentityFile =
            serde_json::from_value(parsed.value().clone()).map_err(|_| IdentityError::Permanent)?;
        if file.auditor.is_empty() || file.operator.is_empty() || file.wallets.is_empty() {
            return Err(IdentityError::Permanent);
        }
        // One credential must resolve to exactly one principal.
        let mut credentials = std::collections::HashSet::new();
        let distinct = [&file.auditor, &file.operator]
            .into_iter()
            .chain(file.wallets.values())
            .all(|credential| credentials.insert(credential.as_str()));
        if !distinct {
            return Err(IdentityError::Permanent);
        }
        let wallets = file
            .wallets
            .into_iter()
            .map(|(wallet, credential)| {
                if credential.is_empty() {
                    return Err(IdentityError::Permanent);
                }
                Ok((
                    WalletId::new(wallet).map_err(|_| IdentityError::Permanent)?,
                    credential.into_bytes(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            wallets,
            auditor: file.auditor.into_bytes(),
            operator: file.operator.into_bytes(),
        })
    }
}

impl Identity for FileIdentity {
    async fn authenticate(&self, credential: &Credential) -> Result<Actor, IdentityError> {
        let presented = credential.expose().as_bytes();
        if constant_time_equal(presented, &self.auditor) {
            return Ok(Actor::Auditor);
        }
        if constant_time_equal(presented, &self.operator) {
            return Ok(Actor::Operator);
        }
        self.wallets
            .iter()
            .find(|(_, expected)| constant_time_equal(presented, expected))
            .map(|(wallet, _)| Actor::Wallet(wallet.clone()))
            .ok_or(IdentityError::Unauthorized)
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

/// A binding record's state. Revocation is terminal from its record's `not_before`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyState {
    Active,
    Revoked,
}

#[derive(Clone)]
struct Binding {
    verified: VerifiedBinding,
    not_before: Timestamp,
    not_after: Option<Timestamp>,
    state: KeyState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRecordDto {
    body: BindingBodyDto,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingBodyDto {
    algorithm: String,
    authority_key_id: String,
    key_id: String,
    not_before: String,
    #[serde(default)]
    not_after: Option<String>,
    public_key: String,
    purpose: String,
    registry_sequence: u64,
    state: String,
    wallet_id: String,
}

/// Append-only, authority-verified mock key registry.
pub struct FileKeyRegistry {
    bindings: Vec<Binding>,
}

impl FileKeyRegistry {
    /// Loads every binding and verifies its authority signature and derived key ID.
    pub fn load(settings: &KeySettings) -> Result<Self, KeyRegistryError> {
        let authority = read_b64_32(&settings.registry_authority_public)
            .map_err(|_| KeyRegistryError::Permanent)?;
        let authority_key_id = format!("reg-ed25519-{}", encode(&sha256(&authority)));
        strict_verify_key(&authority)?;

        let bytes = fs::read(&settings.bindings).map_err(|_| KeyRegistryError::Permanent)?;
        let parsed = parse_bounded_json(&bytes, MAX_PROVIDER_FILE, 16)
            .map_err(|_| KeyRegistryError::InvalidBinding)?;
        let records = parsed
            .value()
            .as_array()
            .filter(|records| !records.is_empty() && records.len() <= 1_024)
            .ok_or(KeyRegistryError::InvalidBinding)?;
        let mut bindings: Vec<Binding> = Vec::with_capacity(records.len());
        for value in records {
            let binding = parse_binding_record(value, &authority, &authority_key_id)?;
            // Sequences start at 1 and strictly increase.
            let previous = bindings
                .last()
                .map_or(0, |previous| previous.verified.sequence);
            if binding.verified.sequence <= previous {
                return Err(KeyRegistryError::InvalidBinding);
            }
            bindings.push(binding);
        }
        check_key_histories(&bindings)?;
        Ok(Self { bindings })
    }

    /// The record in force for one key at `at`, among its records up to registry `sequence`: the
    /// highest-sequence one whose `not_before` has passed. This is the only key-state rule;
    /// [`KeyRegistry::resolve_active`] applies it at the head sequence, and
    /// [`KeyRegistry::effective_as_of`] at a recorded one.
    fn effective<'a>(&'a self, key_id: &str, sequence: u64, at: Timestamp) -> Option<&'a Binding> {
        self.bindings.iter().rev().find(|binding| {
            binding.verified.key_id == key_id
                && binding.verified.sequence <= sequence
                && binding.not_before <= at
        })
    }

    fn head(&self) -> Result<u64, KeyRegistryError> {
        self.bindings
            .last()
            .map(|binding| binding.verified.sequence)
            .ok_or(KeyRegistryError::NotFound)
    }
}

/// Verifies one authority-signed binding record: its authority, signature, purpose and algorithm,
/// canonical key encoding and length, derived key ID, key validity, state, and validity window.
/// Registry order is the caller's concern.
fn parse_binding_record(
    value: &serde_json::Value,
    authority: &[u8; 32],
    authority_key_id: &str,
) -> Result<Binding, KeyRegistryError> {
    let record_bytes = canonicalize(value).map_err(|_| KeyRegistryError::InvalidBinding)?;
    let dto: BindingRecordDto =
        serde_json::from_value(value.clone()).map_err(|_| KeyRegistryError::InvalidBinding)?;
    if dto.body.authority_key_id != authority_key_id {
        return Err(KeyRegistryError::InvalidBinding);
    }
    let body = value.get("body").ok_or(KeyRegistryError::InvalidBinding)?;
    let body_bytes = canonicalize(body).map_err(|_| KeyRegistryError::InvalidBinding)?;
    let mut input = Vec::with_capacity(BINDING_LABEL.len() + 32);
    input.extend_from_slice(BINDING_LABEL);
    input.extend_from_slice(&sha256(&body_bytes));
    let signature = decode_fixed::<64>(&dto.signature)?;
    strict_verify(authority, &input, signature).map_err(|_| KeyRegistryError::InvalidBinding)?;

    let purpose = match dto.body.purpose.as_str() {
        "document-signing" if dto.body.algorithm == "Ed25519" => KeyPurpose::DocumentSigning,
        "document-encryption" if dto.body.algorithm == "X25519" => KeyPurpose::DocumentEncryption,
        _ => return Err(KeyRegistryError::WrongPurpose),
    };
    let public_key = decode_fixed::<32>(&dto.body.public_key)?;
    let prefix = match purpose {
        KeyPurpose::DocumentSigning => "sig-ed25519-",
        KeyPurpose::DocumentEncryption => "kem-x25519-",
    };
    if dto.body.key_id != format!("{prefix}{}", encode(&sha256(&public_key))) {
        return Err(KeyRegistryError::InvalidBinding);
    }
    match purpose {
        KeyPurpose::DocumentSigning => strict_verify_key(&public_key)?,
        KeyPurpose::DocumentEncryption => validate_x25519(&public_key)?,
    }
    let state = match dto.body.state.as_str() {
        "active" => KeyState::Active,
        "revoked" => KeyState::Revoked,
        _ => return Err(KeyRegistryError::InvalidBinding),
    };
    let not_before = Timestamp::parse_rfc3339(&dto.body.not_before)
        .map_err(|_| KeyRegistryError::InvalidBinding)?;
    let not_after = dto
        .body
        .not_after
        .as_deref()
        .map(Timestamp::parse_rfc3339)
        .transpose()
        .map_err(|_| KeyRegistryError::InvalidBinding)?;
    if not_after.is_some_and(|end| end <= not_before) {
        return Err(KeyRegistryError::InvalidBinding);
    }
    Ok(Binding {
        verified: VerifiedBinding {
            wallet: WalletId::new(dto.body.wallet_id)
                .map_err(|_| KeyRegistryError::InvalidBinding)?,
            purpose,
            key_id: dto.body.key_id,
            public_key,
            binding_digest: sha256(&record_bytes),
            sequence: dto.body.registry_sequence,
        },
        not_before,
        not_after,
        state,
    })
}

/// Verifies one canonical binding record against `authority`, exactly as `load` verifies each
/// record, so conformance tests can drive the registry's own key checks.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn verify_binding_record(
    record: &[u8],
    authority: &[u8; 32],
) -> Result<VerifiedBinding, KeyRegistryError> {
    let parsed = parse_bounded_json(record, MAX_PROVIDER_FILE, 16)
        .map_err(|_| KeyRegistryError::InvalidBinding)?;
    let authority_key_id = format!("reg-ed25519-{}", encode(&sha256(authority)));
    parse_binding_record(parsed.value(), authority, &authority_key_id)
        .map(|binding| binding.verified)
}

/// Rejects a registry in which a key ID changes its wallet, purpose, or public key, or becomes
/// active again after a revocation. Revocation is terminal.
fn check_key_histories(bindings: &[Binding]) -> Result<(), KeyRegistryError> {
    for (index, later) in bindings.iter().enumerate() {
        let earlier = bindings
            .get(..index)
            .unwrap_or_default()
            .iter()
            .filter(|binding| binding.verified.key_id == later.verified.key_id);
        for earlier in earlier {
            if earlier.verified.wallet != later.verified.wallet
                || earlier.verified.purpose != later.verified.purpose
                || earlier.verified.public_key != later.verified.public_key
            {
                return Err(KeyRegistryError::InvalidBinding);
            }
            if earlier.state == KeyState::Revoked && later.state == KeyState::Active {
                return Err(KeyRegistryError::InvalidBinding);
            }
        }
    }
    Ok(())
}

/// Why a key's effective record at a given time cannot be used, or `None` when it can.
fn unusable_reason(effective: Option<&Binding>, at: Timestamp) -> Option<KeyRegistryError> {
    match effective {
        None => Some(KeyRegistryError::Inactive),
        Some(binding) if binding.state == KeyState::Revoked => Some(KeyRegistryError::Revoked),
        Some(binding) if binding.not_after.is_some_and(|end| at >= end) => {
            Some(KeyRegistryError::Expired)
        }
        Some(_) => None,
    }
}

impl KeyRegistry for FileKeyRegistry {
    async fn resolve_active(
        &self,
        wallet: &WalletId,
        purpose: KeyPurpose,
        at: Timestamp,
    ) -> Result<VerifiedBinding, KeyRegistryError> {
        // Candidate key IDs, newest first by their latest record.
        let mut candidates: Vec<&str> = Vec::new();
        for binding in self.bindings.iter().rev() {
            if binding.verified.wallet == *wallet
                && binding.verified.purpose == purpose
                && !candidates.contains(&binding.verified.key_id.as_str())
            {
                candidates.push(&binding.verified.key_id);
            }
        }
        let newest = candidates.first().ok_or(KeyRegistryError::NotFound)?;
        let head = self.head()?;
        let usable = candidates
            .iter()
            .filter_map(|key_id| self.effective(key_id, head, at))
            .filter(|binding| unusable_reason(Some(binding), at).is_none())
            .max_by_key(|binding| binding.verified.sequence);
        match usable {
            Some(binding) => Ok(binding.verified.clone()),
            None => Err(unusable_reason(self.effective(newest, head, at), at)
                .unwrap_or(KeyRegistryError::NotFound)),
        }
    }

    async fn load(&self, binding_digest: &[u8; 32]) -> Result<VerifiedBinding, KeyRegistryError> {
        self.bindings
            .iter()
            .find(|binding| binding.verified.binding_digest == *binding_digest)
            .map(|binding| binding.verified.clone())
            .ok_or(KeyRegistryError::NotFound)
    }

    async fn effective_as_of(
        &self,
        key_id: &str,
        sequence: u64,
        at: Timestamp,
    ) -> Result<VerifiedBinding, KeyRegistryError> {
        if !self.bindings.iter().any(|binding| {
            binding.verified.key_id == key_id && binding.verified.sequence <= sequence
        }) {
            return Err(KeyRegistryError::NotFound);
        }
        let effective = self.effective(key_id, sequence, at);
        if let Some(reason) = unusable_reason(effective, at) {
            return Err(reason);
        }
        effective
            .map(|binding| binding.verified.clone())
            .ok_or(KeyRegistryError::Inactive)
    }

    async fn head_sequence(&self) -> Result<u64, KeyRegistryError> {
        self.head()
    }
}

/// Separate Ed25519 audit key for events and checkpoints.
pub struct AuditKey(SigningKey);

impl AuditKey {
    pub(crate) fn load(path: &std::path::Path) -> Result<Self, IntegrityError> {
        read_b64_32(path)
            .map(SigningKey::from)
            .map(Self)
            .map_err(|_| IntegrityError::Invariant)
    }
}

impl EventIntegrity for AuditKey {
    fn public_key(&self) -> Result<[u8; 32], IntegrityError> {
        Ok(VerificationKey::from(&self.0).into())
    }

    fn sign(&self, input: &[u8]) -> Result<[u8; 64], IntegrityError> {
        Ok(self.0.sign(input).into())
    }

    fn verify(&self, input: &[u8], signature: &[u8; 64]) -> Result<(), IntegrityError> {
        let public: [u8; 32] = VerificationKey::from(&self.0).into();
        strict_verify(&public, input, *signature).map_err(|_| IntegrityError::AuthenticationFailed)
    }
}

/// Wall clock read only through the clock port.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            });
        Timestamp::from_unix_seconds(seconds)
    }
}

pub(crate) fn load_key_files(paths: &[std::path::PathBuf]) -> Result<Vec<[u8; 32]>, ()> {
    paths.iter().map(|path| read_b64_32(path)).collect()
}

fn read_b64_32(path: &std::path::Path) -> Result<[u8; 32], ()> {
    let text = fs::read_to_string(path).map_err(|_| ())?;
    decode_fixed::<32>(text.trim()).map_err(|_| ())
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], KeyRegistryError> {
    if value.contains('=') || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(KeyRegistryError::InvalidBinding);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| KeyRegistryError::InvalidBinding)?;
    if encode(&bytes) != value {
        return Err(KeyRegistryError::InvalidBinding);
    }
    bytes
        .try_into()
        .map_err(|_| KeyRegistryError::InvalidBinding)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn strict_verify_key(public: &[u8; 32]) -> Result<(), KeyRegistryError> {
    valid_ed25519_public(public)
        .then_some(())
        .ok_or(KeyRegistryError::InvalidBinding)
}

fn validate_x25519(public: &[u8; 32]) -> Result<(), KeyRegistryError> {
    if public.iter().all(|byte| *byte == 0) {
        Err(KeyRegistryError::InvalidBinding)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use serde_json::{Value, json};

    use super::*;

    const FIXTURE: &str = include_str!("../../../tests/vectors/envelope-v1.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("vector fixture")
    }

    /// A per-test directory, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let directory =
            std::env::temp_dir().join(format!("docchain_provider_{}_{name}", std::process::id()));
        fs::create_dir_all(&directory).expect("scratch directory");
        Scratch(directory)
    }

    fn vector_records() -> Vec<Value> {
        fixture()["expected"]["binding_records"]
            .as_array()
            .expect("binding records")
            .iter()
            .map(|record| serde_json::from_str(record.as_str().expect("record")).expect("json"))
            .collect()
    }

    /// Writes the registry files and returns settings naming them.
    fn registry_files(directory: &Path, authority: &str, records: &[Value]) -> KeySettings {
        let authority_path = directory.join("authority.key");
        let bindings_path = directory.join("bindings.json");
        fs::write(&authority_path, authority).expect("authority file");
        fs::write(&bindings_path, Value::from(records.to_vec()).to_string()).expect("bindings");
        KeySettings {
            registry_authority_public: authority_path,
            bindings: bindings_path,
            wallet_signing_private: Vec::new(),
            wallet_encryption_private: Vec::new(),
            audit_private: directory.join("unused"),
            audit_public_key_fingerprint: [0; 32],
        }
    }

    fn vector_authority() -> String {
        fixture()["expected"]["registry_public_key"]
            .as_str()
            .expect("registry key")
            .to_owned()
    }

    /// Signs a binding body with the vector's registry authority, as the authority would.
    fn signed(body: Value) -> Value {
        let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).expect("index"));
        let authority = SigningKey::from(seed);
        let digest = sha256(&canonicalize(&body).expect("canonical body"));
        let signature: [u8; 64] = authority
            .sign(&[BINDING_LABEL, digest.as_slice()].concat())
            .into();
        json!({"body": body, "signature": encode(&signature)})
    }

    fn digest(record: &Value) -> [u8; 32] {
        sha256(&canonicalize(record).expect("canonical record"))
    }

    fn wallet(value: &str) -> WalletId {
        WalletId::new(value).expect("wallet")
    }

    fn at(value: &str) -> Timestamp {
        Timestamp::parse_rfc3339(value).expect("timestamp")
    }

    #[tokio::test]
    async fn registry_verifies_vector_bindings_and_resolves_active_keys() {
        let records = vector_records();
        let directory = scratch("vector");
        let settings = registry_files(directory.path(), &vector_authority(), &records);
        let registry = FileKeyRegistry::load(&settings).expect("authentic registry");

        let signing = registry
            .resolve_active(
                &wallet("wal_0000000000000001"),
                KeyPurpose::DocumentSigning,
                at("2026-09-20T00:00:00Z"),
            )
            .await
            .expect("active signing binding");
        assert_eq!(signing.binding_digest, digest(&records[0]));
        assert_eq!(
            registry
                .load(&digest(&records[2]))
                .await
                .map(|b| b.sequence),
            Ok(3)
        );
        assert_eq!(registry.head_sequence().await, Ok(3));
        assert_eq!(
            registry
                .resolve_active(
                    &wallet("wal_0000000000000001"),
                    KeyPurpose::DocumentSigning,
                    at("2026-09-18T00:00:00Z"),
                )
                .await,
            Err(KeyRegistryError::Inactive)
        );
        assert_eq!(
            registry
                .resolve_active(
                    &wallet("wal_0000000000000003"),
                    KeyPurpose::DocumentEncryption,
                    at("2026-09-20T00:00:00Z"),
                )
                .await,
            Err(KeyRegistryError::NotFound)
        );
    }

    #[test]
    fn registry_rejects_forged_foreign_reordered_or_underived_bindings() {
        let directory = scratch("rejects");
        let mut forged = vector_records();
        forged[2]["body"]["wallet_id"] = json!("wal_0000000000000003");

        let mut reordered = vector_records();
        reordered.swap(0, 1);

        let mut underived_body = vector_records()[2]["body"].clone();
        underived_body["registry_sequence"] = json!(4);
        underived_body["key_id"] = vector_records()[1]["body"]["key_id"].clone();
        let mut underived = vector_records();
        underived.push(signed(underived_body));

        let mut wrong_purpose_body = vector_records()[0]["body"].clone();
        wrong_purpose_body["registry_sequence"] = json!(4);
        wrong_purpose_body["purpose"] = json!("document-encryption");
        let mut wrong_purpose = vector_records();
        wrong_purpose.push(signed(wrong_purpose_body));

        let foreign_authority: [u8; 32] =
            VerificationKey::from(&SigningKey::from([9_u8; 32])).into();

        for (case, authority, records) in [
            ("forged wallet", vector_authority(), forged),
            ("non-increasing sequence", vector_authority(), reordered),
            ("key ID not derived from key", vector_authority(), underived),
            ("wrong purpose", vector_authority(), wrong_purpose),
            (
                "foreign authority",
                encode(&foreign_authority),
                vector_records(),
            ),
        ] {
            let settings = registry_files(directory.path(), &authority, &records);
            assert!(FileKeyRegistry::load(&settings).is_err(), "{case}");
        }
    }

    #[tokio::test]
    async fn registry_applies_revocation_from_its_sequence_only() {
        let mut records = vector_records();
        let mut revocation = records[2]["body"].clone();
        revocation["registry_sequence"] = json!(4);
        revocation["state"] = json!("revoked");
        records.push(signed(revocation));
        let directory = scratch("revocation");
        let settings = registry_files(directory.path(), &vector_authority(), &records);
        let registry = FileKeyRegistry::load(&settings).expect("authentic registry");
        let key_id = records[2]["body"]["key_id"].as_str().expect("key id");

        assert_eq!(
            registry
                .resolve_active(
                    &wallet("wal_0000000000000002"),
                    KeyPurpose::DocumentEncryption,
                    at("2026-09-20T00:00:00Z"),
                )
                .await,
            Err(KeyRegistryError::Revoked)
        );
        let now = at("2026-09-20T00:00:00Z");
        assert_eq!(
            registry
                .effective_as_of(key_id, 3, now)
                .await
                .map(|binding| binding.binding_digest),
            Ok(digest(&records[2]))
        );
        assert_eq!(
            registry.effective_as_of(key_id, 4, now).await,
            Err(KeyRegistryError::Revoked)
        );
        assert_eq!(
            registry.effective_as_of(key_id, 2, now).await,
            Err(KeyRegistryError::NotFound)
        );
    }

    /// An authority-signed encryption binding for an invented X25519 public key.
    fn encryption_record(
        wallet_id: &str,
        public: [u8; 32],
        sequence: u64,
        state: &str,
        not_before: &str,
    ) -> Value {
        encryption_record_until(wallet_id, public, sequence, state, not_before, None)
    }

    /// As [`encryption_record`], with an optional end of validity.
    fn encryption_record_until(
        wallet_id: &str,
        public: [u8; 32],
        sequence: u64,
        state: &str,
        not_before: &str,
        not_after: Option<&str>,
    ) -> Value {
        let mut body = json!({
            "algorithm": "X25519",
            "authority_key_id": vector_records()[0]["body"]["authority_key_id"].clone(),
            "key_id": format!("kem-x25519-{}", encode(&sha256(&public))),
            "not_before": not_before,
            "public_key": encode(&public),
            "purpose": "document-encryption",
            "registry_sequence": sequence,
            "state": state,
            "wallet_id": wallet_id,
        });
        if let Some(end) = not_after {
            body["not_after"] = json!(end);
        }
        signed(body)
    }

    fn load_records(name: &str, records: &[Value]) -> Result<FileKeyRegistry, KeyRegistryError> {
        let directory = scratch(name);
        let settings = registry_files(directory.path(), &vector_authority(), records);
        FileKeyRegistry::load(&settings)
    }

    async fn resolve_recipient(
        registry: &FileKeyRegistry,
        when: &str,
    ) -> Result<VerifiedBinding, KeyRegistryError> {
        registry
            .resolve_active(
                &wallet("wal_0000000000000002"),
                KeyPurpose::DocumentEncryption,
                at(when),
            )
            .await
    }

    #[test]
    fn load_rejects_a_key_id_rebound_to_another_wallet() {
        let mut records = vector_records();
        let mut rebound = records[2]["body"].clone();
        rebound["registry_sequence"] = json!(4);
        rebound["wallet_id"] = json!("wal_0000000000000003");
        records.push(signed(rebound));
        assert_eq!(
            load_records("rebound_wallet", &records).err(),
            Some(KeyRegistryError::InvalidBinding)
        );
    }

    #[test]
    fn load_rejects_a_key_id_rebound_to_another_purpose() {
        let mut records = vector_records();
        let mut rebound = records[0]["body"].clone();
        rebound["registry_sequence"] = json!(4);
        rebound["purpose"] = json!("document-encryption");
        rebound["algorithm"] = json!("X25519");
        records.push(signed(rebound));
        assert!(load_records("rebound_purpose", &records).is_err());
    }

    #[test]
    fn load_rejects_reactivating_a_revoked_key() {
        let mut records = vector_records();
        let mut revoked = records[2]["body"].clone();
        revoked["registry_sequence"] = json!(4);
        revoked["state"] = json!("revoked");
        let mut reactivated = records[2]["body"].clone();
        reactivated["registry_sequence"] = json!(5);
        records.push(signed(revoked));
        records.push(signed(reactivated));
        assert_eq!(
            load_records("reactivated", &records).err(),
            Some(KeyRegistryError::InvalidBinding)
        );
    }

    #[tokio::test]
    async fn resolve_active_skips_a_revoked_old_key_after_rotation() {
        let mut records = vector_records();
        let rotated = [7_u8; 32];
        records.push(encryption_record(
            "wal_0000000000000002",
            rotated,
            4,
            "active",
            "2026-09-19T00:00:00Z",
        ));
        let mut revoked_old = records[2]["body"].clone();
        revoked_old["registry_sequence"] = json!(5);
        revoked_old["state"] = json!("revoked");
        records.push(signed(revoked_old));
        let registry = load_records("rotation", &records).expect("registry");

        let resolved = resolve_recipient(&registry, "2026-09-20T00:00:00Z")
            .await
            .expect("the rotated key stays usable");
        assert_eq!(resolved.public_key, rotated);
        assert_eq!(resolved.sequence, 4);
    }

    #[tokio::test]
    async fn resolve_active_skips_a_not_yet_valid_binding() {
        let mut records = vector_records();
        records.push(encryption_record(
            "wal_0000000000000002",
            [8_u8; 32],
            4,
            "active",
            "2026-10-01T00:00:00Z",
        ));
        let registry = load_records("future", &records).expect("registry");

        let before = resolve_recipient(&registry, "2026-09-20T00:00:00Z")
            .await
            .expect("the current key is used until the new one is valid");
        assert_eq!(before.sequence, 3);
        let after = resolve_recipient(&registry, "2026-10-02T00:00:00Z")
            .await
            .expect("the newer key once valid");
        assert_eq!(after.sequence, 4);
    }

    #[tokio::test]
    async fn resolve_active_reports_revoked_when_no_usable_key_remains() {
        let mut records = vector_records();
        records.push(encryption_record(
            "wal_0000000000000002",
            [7_u8; 32],
            4,
            "active",
            "2026-09-19T00:00:00Z",
        ));
        for (sequence, record) in [(5, 2_usize), (6, 3)] {
            let mut revoked = records[record]["body"].clone();
            revoked["registry_sequence"] = json!(sequence);
            revoked["state"] = json!("revoked");
            records.push(signed(revoked));
        }
        let registry = load_records("all_revoked", &records).expect("registry");
        assert_eq!(
            resolve_recipient(&registry, "2026-09-20T00:00:00Z").await,
            Err(KeyRegistryError::Revoked)
        );
    }

    #[tokio::test]
    async fn revocation_takes_effect_at_its_not_before() {
        let mut records = vector_records();
        let mut revoked = records[2]["body"].clone();
        revoked["registry_sequence"] = json!(4);
        revoked["state"] = json!("revoked");
        revoked["not_before"] = json!("2026-09-25T00:00:00Z");
        records.push(signed(revoked));
        let registry = load_records("scheduled_revocation", &records).expect("registry");
        let key_id = records[2]["body"]["key_id"].as_str().expect("key id");

        assert_eq!(
            resolve_recipient(&registry, "2026-09-24T23:59:59Z")
                .await
                .map(|binding| binding.sequence),
            Ok(3)
        );
        assert_eq!(
            resolve_recipient(&registry, "2026-09-25T00:00:00Z").await,
            Err(KeyRegistryError::Revoked)
        );
        assert_eq!(
            registry
                .effective_as_of(key_id, 4, at("2026-09-24T23:59:59Z"))
                .await
                .map(|binding| binding.sequence),
            Ok(3)
        );
        assert_eq!(
            registry
                .effective_as_of(key_id, 4, at("2026-09-25T00:00:00Z"))
                .await,
            Err(KeyRegistryError::Revoked)
        );
    }

    /// The vector's records; sequence 4 revokes the recipient's encryption key from
    /// `2026-09-25T00:00:00Z`, and sequence 5 binds a third wallet's key valid until
    /// `2026-09-30T00:00:00Z`.
    fn commit_time_records() -> Vec<Value> {
        let mut records = vector_records();
        let mut revoked = records[2]["body"].clone();
        revoked["registry_sequence"] = json!(4);
        revoked["state"] = json!("revoked");
        revoked["not_before"] = json!("2026-09-25T00:00:00Z");
        records.push(signed(revoked));
        records.push(encryption_record_until(
            "wal_0000000000000003",
            [7_u8; 32],
            5,
            "active",
            "2026-09-19T00:00:00Z",
            Some("2026-09-30T00:00:00Z"),
        ));
        records
    }

    #[tokio::test]
    async fn effective_as_of_judges_at_the_commit_time() {
        let records = commit_time_records();
        let registry = load_records("commit_time", &records).expect("registry");
        let recipient_key = records[2]["body"]["key_id"].as_str().expect("key id");
        let expiring_key = records[4]["body"]["key_id"].as_str().expect("key id");
        let before_revocation = at("2026-09-24T23:59:59Z");
        let revocation = at("2026-09-25T00:00:00Z");

        let in_force = registry
            .effective_as_of(recipient_key, 4, before_revocation)
            .await
            .expect("the active record is in force before the revocation");
        assert_eq!(in_force.binding_digest, digest(&records[2]));
        assert_eq!(
            resolve_recipient(&registry, "2026-09-24T23:59:59Z").await,
            Ok(in_force)
        );
        assert_eq!(
            registry.effective_as_of(recipient_key, 4, revocation).await,
            Err(KeyRegistryError::Revoked)
        );
        assert_eq!(
            registry
                .effective_as_of(recipient_key, 3, revocation)
                .await
                .map(|binding| binding.binding_digest),
            Ok(digest(&records[2])),
            "a record after the sequence does not change the result"
        );
        assert_eq!(
            registry
                .effective_as_of(recipient_key, 4, at("2026-09-18T23:59:59Z"))
                .await,
            Err(KeyRegistryError::Inactive)
        );
        assert_eq!(
            registry
                .effective_as_of(expiring_key, 5, at("2026-09-29T23:59:59Z"))
                .await
                .map(|binding| binding.binding_digest),
            Ok(digest(&records[4]))
        );
        assert_eq!(
            registry
                .effective_as_of(expiring_key, 5, at("2026-09-30T00:00:00Z"))
                .await,
            Err(KeyRegistryError::Expired)
        );
        assert_eq!(
            registry
                .effective_as_of(expiring_key, 4, before_revocation)
                .await,
            Err(KeyRegistryError::NotFound)
        );
        assert_eq!(
            registry
                .effective_as_of("kem-x25519-unknown", 5, before_revocation)
                .await,
            Err(KeyRegistryError::NotFound)
        );
    }

    #[tokio::test]
    async fn effective_as_of_agrees_with_resolve_active() {
        let records = commit_time_records();
        let registry = load_records("agreement", &records).expect("registry");
        let head = registry.head_sequence().await.expect("head");
        let mut times = Vec::new();
        for boundary in [
            "2026-09-19T00:00:00Z",
            "2026-09-25T00:00:00Z",
            "2026-09-30T00:00:00Z",
        ] {
            let seconds = at(boundary).unix_seconds();
            times.extend([seconds - 1, seconds, seconds + 1].map(Timestamp::from_unix_seconds));
        }
        let owners = [
            ("wal_0000000000000001", KeyPurpose::DocumentSigning),
            ("wal_0000000000000001", KeyPurpose::DocumentEncryption),
            ("wal_0000000000000002", KeyPurpose::DocumentEncryption),
            ("wal_0000000000000003", KeyPurpose::DocumentEncryption),
        ];
        for (owner, purpose) in owners {
            // The newest key for the owner: the key ID of its latest record.
            let newest = records
                .iter()
                .rev()
                .find(|record| {
                    record["body"]["wallet_id"] == json!(owner)
                        && record["body"]["purpose"]
                            == json!(match purpose {
                                KeyPurpose::DocumentSigning => "document-signing",
                                KeyPurpose::DocumentEncryption => "document-encryption",
                            })
                })
                .and_then(|record| record["body"]["key_id"].as_str())
                .expect("owner has a key");
            for when in &times {
                let resolved = registry
                    .resolve_active(&wallet(owner), purpose, *when)
                    .await;
                match &resolved {
                    Ok(binding) => assert_eq!(
                        registry.effective_as_of(&binding.key_id, head, *when).await,
                        resolved,
                        "{owner} {purpose:?} at {when:?}"
                    ),
                    Err(error) => assert_eq!(
                        registry.effective_as_of(newest, head, *when).await,
                        Err(*error),
                        "{owner} {purpose:?} at {when:?}"
                    ),
                }
            }
        }
    }

    #[tokio::test]
    async fn approved_digest_is_pinned_not_derived() {
        let vector_digest = fixture()["expected"]["schema_digest"]
            .as_str()
            .expect("schema digest")
            .to_owned();
        assert_eq!(encode(&APPROVED_SERVICE_APPLICATION_DIGEST), vector_digest);
        let parsed = parse_bounded_json(SERVICE_APPLICATION_SCHEMA, 64 * 1024, 32).expect("schema");
        assert_eq!(sha256(parsed.bytes()), APPROVED_SERVICE_APPLICATION_DIGEST);
        let artifact = StaticSchemaRegistry
            .load_active("urn:docchain:schema:service-application:1.0.0", "1.0.0")
            .await
            .expect("artifact");
        assert_eq!(
            artifact.approved_digest,
            APPROVED_SERVICE_APPLICATION_DIGEST
        );
    }

    #[tokio::test]
    async fn identity_verifies_configured_credentials_only() {
        let directory = scratch("identity");
        let path = directory.path().join("identities.json");
        fs::write(
            &path,
            json!({
                "wallets": {"wal_0000000000000001": "wallet-one", "wal_0000000000000002": "wallet-two"},
                "auditor": "auditor", "operator": "operator"
            })
            .to_string(),
        )
        .expect("identity file");
        let identity = FileIdentity::load(&path).expect("identity");
        let credential = |value: &str| Credential::new(value.to_owned());

        assert_eq!(
            identity.authenticate(&credential("wallet-two")).await,
            Ok(Actor::Wallet(wallet("wal_0000000000000002")))
        );
        assert_eq!(
            identity.authenticate(&credential("auditor")).await,
            Ok(Actor::Auditor)
        );
        assert_eq!(
            identity.authenticate(&credential("operator")).await,
            Ok(Actor::Operator)
        );
        for forged in ["wal_0000000000000001", "wallet-on", "wallet-one ", ""] {
            assert_eq!(
                identity.authenticate(&credential(forged)).await,
                Err(IdentityError::Unauthorized),
                "{forged}"
            );
        }

        fs::write(
            &path,
            json!({
                "wallets": {"wal_0000000000000001": "shared"},
                "auditor": "shared", "operator": "operator"
            })
            .to_string(),
        )
        .expect("identity file");
        assert!(FileIdentity::load(&path).is_err());
    }

    #[test]
    fn credential_comparison_checks_length_and_bytes() {
        assert!(constant_time_equal(b"secret", b"secret"));
        assert!(!constant_time_equal(b"secret", b"secreu"));
        assert!(!constant_time_equal(b"secret", b"secret-long"));
    }
}
