//! Version 1 document envelope: canonical signing, content encryption, and HPKE key wrapping.
//!
//! # Conformance statement
//!
//! Every check that rejects an envelope happens before any plaintext is returned, and the port
//! reports only [`CryptoError`]; the internal stage at which a check fails is never logged,
//! returned, or shown in a response.
//!
//! Secret material that this module owns is cleared on every exit path, including errors: the
//! 108-byte random buffer, held in `Zeroizing` and passed by reference; each copy of the content
//! key; each HPKE ephemeral seed and the fixed generator that serves it; and the signed payload
//! buffers on both the seal and open paths.
//!
//! On the send path, the document bytes Docchain owns are overwritten when they are dropped: the
//! raw document in `SendCopyCommand`, into which the HTTP adapter moves the canonical bytes
//! without keeping another copy, and the canonical bytes in each `CanonicalDocument`, including
//! the strictly parsed request body.
//!
//! Some copies cannot be cleared from here:
//!
//! - copies inside libraries: `hpke` key schedules and ephemeral keys, `ed25519-consensus` signing
//!   keys, which have no zeroize feature, and `serde_json` values built while parsing, including
//!   the document value in the request DTO and the parsed value inside each `CanonicalDocument`;
//! - the request body bytes, which the HTTP server owns;
//! - copies the compiler or allocator makes when values move or buffers grow;
//! - the response body once the HTTP server owns it.

use std::{convert::Infallible, fs::File, io::Read};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305 as ContentAead, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use docchain_application::{
    CryptoError, EnvelopeCryptography, EnvelopeHeader, HeaderKey, KeyPurpose, OpenRequest,
    Plaintext, SealRequest, SealedEnvelope, VerifiedBinding,
};
#[cfg(any(test, feature = "test-support"))]
use docchain_domain::RequestNonce;
use docchain_domain::{
    DocumentId, DocumentVersion, MAX_DOCUMENT_BYTES, WalletId, canonicalize, parse_bounded_json,
    parse_document, sha256,
};
use ed25519_consensus::{Signature, SigningKey, VerificationKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305 as HpkeAead,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{TryCryptoRng, TryRng},
    setup_receiver, setup_sender_with_rng,
};
#[cfg(any(test, feature = "test-support"))]
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

type Kem = X25519HkdfSha256;
const SIGNATURE_LABEL: &[u8] = b"docchain/envelope/v1/signature\0";
const CONTENT_AAD_LABEL: &[u8] = b"docchain/envelope/v1/content-aad\0";
const HPKE_INFO_LABEL: &[u8] = b"docchain/envelope/v1/hpke-info\0";
const HPKE_AAD_LABEL: &[u8] = b"docchain/envelope/v1/hpke-aad\0";
const MAX_PROTECTED_BYTES: usize = 4 * 1024;
const MAX_ENVELOPE_BYTES: usize = 360 * 1024;
const MAX_ENVELOPE_DEPTH: usize = 5;
const RANDOM_BYTES: usize = 108;

/// The check that rejected an envelope operation, one per conformance-fixture rejection stage.
///
/// It stays inside this module: the port result is only the [`CryptoError`], so a caller cannot
/// learn which check failed. Tests compare it with the fixture's stage for each mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectionStage {
    /// Strict parse before schema validation.
    StrictParse,
    /// Strict profile before schema validation. The domain parser owns this gate, on the send
    /// path; only the conformance runner reports it.
    #[cfg(any(test, feature = "test-support"))]
    StrictProfile,
    /// Before encryption or commit.
    BeforeEncryption,
    /// Binding validation before cryptography.
    BindingValidation,
    /// Key validation before storage or plaintext.
    KeyValidation,
    /// Protected-header validation without fallback.
    ProtectedHeader,
    /// Protected-hash binding before plaintext.
    ProtectedHashBinding,
    /// Content opening before plaintext.
    ContentOpening,
    /// Recipient wrapper opening.
    RecipientWrapper,
    /// Digest or signature verification before plaintext.
    Verification,
    /// Exact payload length before document parsing.
    PayloadLength,
    /// Before object write or event.
    BeforeObjectWrite,
}

impl RejectionStage {
    /// The fixture's `rejection_stage` text for this stage.
    #[cfg(any(test, feature = "test-support"))]
    const fn fixture_text(self) -> &'static str {
        match self {
            Self::StrictParse => "strict parse before schema validation",
            #[cfg(any(test, feature = "test-support"))]
            Self::StrictProfile => "strict profile before schema validation",
            Self::BeforeEncryption => "before encryption or commit",
            Self::BindingValidation => "binding validation before cryptography",
            Self::KeyValidation => "key validation before storage or plaintext",
            Self::ProtectedHeader => "protected-header validation without fallback",
            Self::ProtectedHashBinding => "protected-hash binding before plaintext",
            Self::ContentOpening => "content opening before plaintext",
            Self::RecipientWrapper => "recipient wrapper opening",
            Self::Verification => "digest or signature verification before plaintext",
            Self::PayloadLength => "exact payload length before document parsing",
            Self::BeforeObjectWrite => "before object write or event",
        }
    }

    /// Tags an error with this stage.
    const fn with(self, error: CryptoError) -> Rejection {
        Rejection { stage: self, error }
    }
}

/// A port error together with the internal stage that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rejection {
    stage: RejectionStage,
    error: CryptoError,
}

type Staged<T> = Result<T, Rejection>;

trait Entropy: Send + Sync {
    fn fill(&self, destination: &mut [u8]) -> Result<(), CryptoError>;
}

#[derive(Debug)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, destination: &mut [u8]) -> Result<(), CryptoError> {
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(destination))
            .map_err(|_| CryptoError::EntropyExhausted)
    }
}

struct EncryptionPrivate {
    private: <Kem as KemTrait>::PrivateKey,
    key_id: String,
}

pub struct CryptoEngine<E = OsEntropy> {
    entropy: E,
    signing: Vec<(String, SigningKey)>,
    encryption: Vec<EncryptionPrivate>,
}

impl CryptoEngine<OsEntropy> {
    /// Builds the cryptographic adapter from configured mock-wallet key files.
    ///
    /// Signing values are Ed25519 seeds; encryption values are RFC 9180 X25519 key-generation
    /// inputs. The derived IDs must be the IDs authenticated by the key registry.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for duplicate or malformed configured material.
    pub fn new(
        signing_seeds: Vec<[u8; 32]>,
        encryption_inputs: Vec<[u8; 32]>,
    ) -> Result<Self, CryptoError> {
        Self::from_material(signing_seeds, encryption_inputs, OsEntropy)
    }
}

impl<E> CryptoEngine<E> {
    fn from_material(
        signing_seeds: Vec<[u8; 32]>,
        encryption_inputs: Vec<[u8; 32]>,
        entropy: E,
    ) -> Result<Self, CryptoError> {
        if signing_seeds.is_empty() || encryption_inputs.is_empty() {
            return Err(CryptoError::InvalidKey);
        }
        let signing = signing_seeds
            .into_iter()
            .map(|seed| {
                let key = SigningKey::from(seed);
                let public: [u8; 32] = VerificationKey::from(&key).into();
                (format!("sig-ed25519-{}", b64(&sha256(&public))), key)
            })
            .collect::<Vec<_>>();
        let encryption = encryption_inputs
            .into_iter()
            .map(|input| {
                let (private, public) = Kem::derive_keypair(&input);
                let key_id = format!("kem-x25519-{}", b64(&sha256(public.to_bytes().as_ref())));
                EncryptionPrivate { private, key_id }
            })
            .collect::<Vec<_>>();
        if has_duplicate_ids(signing.iter().map(|(id, _)| id.as_str()))
            || has_duplicate_ids(encryption.iter().map(|key| key.key_id.as_str()))
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            entropy,
            signing,
            encryption,
        })
    }

    /// Seals one document with the supplied random bytes: content key `0..32`, content nonce
    /// `32..44`, and HPKE ephemeral seed `i` at `44 + 32i..76 + 32i`.
    fn seal_staged(
        &self,
        request: &SealRequest<'_>,
        random: &Zeroizing<[u8; RANDOM_BYTES]>,
    ) -> Staged<SealedEnvelope> {
        if request.canonical_document.len() > MAX_DOCUMENT_BYTES {
            return Err(RejectionStage::BeforeEncryption.with(CryptoError::InvalidInput));
        }
        let recipients = sorted_recipients(request.recipients);
        let content_key = Zeroizing::new(
            <[u8; 32]>::try_from(&random[0..32])
                .map_err(|_| RejectionStage::BeforeEncryption.with(CryptoError::Permanent))?,
        );
        let content_nonce = <[u8; 12]>::try_from(&random[32..44])
            .map_err(|_| RejectionStage::BeforeEncryption.with(CryptoError::Permanent))?;
        let protected = build_protected(request, &recipients, content_nonce)
            .map_err(|error| RejectionStage::BeforeEncryption.with(error))?;
        let protected_hash = sha256(&protected);

        let signing = self
            .signing
            .iter()
            .find(|(id, _)| id == &request.sender_signing.key_id)
            .map(|(_, key)| key)
            .ok_or(RejectionStage::BindingValidation.with(CryptoError::InvalidKey))?;
        let payload = signed_payload(signing, &protected_hash, request.canonical_document)
            .map_err(|error| RejectionStage::BeforeEncryption.with(error))?;
        let ciphertext = encrypt_content(
            &payload,
            &content_key,
            content_nonce,
            &content_aad(&protected_hash),
        )
        .map_err(|error| RejectionStage::BeforeEncryption.with(error))?;
        drop(payload);

        let mut wrapped = Vec::with_capacity(recipients.len());
        for (index, binding) in recipients.iter().enumerate() {
            let offset = 44 + index * 32;
            let seed = Zeroizing::new(
                <[u8; 32]>::try_from(random.get(offset..offset + 32).ok_or(
                    RejectionStage::BeforeObjectWrite.with(CryptoError::EntropyExhausted),
                )?)
                .map_err(|_| RejectionStage::BeforeObjectWrite.with(CryptoError::Permanent))?,
            );
            let descriptor = recipient_descriptor(binding)
                .map_err(|error| RejectionStage::BeforeEncryption.with(error))?;
            let (enc, wrapped_key) = wrap_content_key(
                &binding.public_key,
                &hpke_info(&protected_hash),
                &hpke_aad(&protected_hash, &descriptor),
                &content_key,
                &seed,
            )?;
            wrapped.push(json!({
                "enc": b64(&enc),
                "wrapped_key": b64(&wrapped_key),
            }));
        }
        drop(content_key);

        let bytes = assemble_envelope(&protected, &ciphertext, wrapped)
            .map_err(|error| RejectionStage::BeforeEncryption.with(error))?;
        Ok(SealedEnvelope {
            commitment: sha256(&bytes),
            protected_hash,
            envelope_version: 1,
            bytes,
        })
    }
}

/// Orders encryption bindings by the unsigned UTF-8 bytes of the wallet ID, then of the key ID.
///
/// The protected descriptors, the recipient keys, the HPKE seeds, and the wrappers all follow this
/// one order, so wrapper `i` always belongs to protected recipient `i`.
fn sorted_recipients(recipients: [&VerifiedBinding; 2]) -> [&VerifiedBinding; 2] {
    let mut sorted = recipients;
    sorted.sort_by(|left, right| {
        left.wallet
            .as_str()
            .as_bytes()
            .cmp(right.wallet.as_str().as_bytes())
            .then_with(|| left.key_id.as_bytes().cmp(right.key_id.as_bytes()))
    });
    sorted
}

fn recipient_descriptor(binding: &VerifiedBinding) -> Result<Vec<u8>, CryptoError> {
    canonicalize(&json!({
        "binding_digest": b64(&binding.binding_digest),
        "encryption_key_id": binding.key_id,
        "wallet_id": binding.wallet.as_str(),
    }))
    .map_err(|_| CryptoError::InvalidInput)
}

fn content_aad(protected_hash: &[u8; 32]) -> Vec<u8> {
    [CONTENT_AAD_LABEL, protected_hash.as_slice()].concat()
}

fn hpke_info(protected_hash: &[u8; 32]) -> Vec<u8> {
    [HPKE_INFO_LABEL, protected_hash.as_slice()].concat()
}

fn hpke_aad(protected_hash: &[u8; 32], descriptor: &[u8]) -> Vec<u8> {
    [
        HPKE_AAD_LABEL,
        protected_hash.as_slice(),
        sha256(descriptor).as_slice(),
    ]
    .concat()
}

/// `DCP1 || length || document || SHA-256(document) || Ed25519 signature`.
fn signed_payload(
    signing: &SigningKey,
    protected_hash: &[u8; 32],
    document: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let digest = Zeroizing::new(sha256(document));
    let signature_input = Zeroizing::new(
        [
            SIGNATURE_LABEL,
            protected_hash.as_slice(),
            digest.as_slice(),
        ]
        .concat(),
    );
    let signature: [u8; 64] = signing.sign(&signature_input).into();
    let length = u32::try_from(document.len()).map_err(|_| CryptoError::InvalidInput)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(4 + 4 + document.len() + 32 + 64));
    payload.extend_from_slice(b"DCP1");
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(document);
    payload.extend_from_slice(digest.as_slice());
    payload.extend_from_slice(&signature);
    Ok(payload)
}

fn encrypt_content(
    payload: &[u8],
    content_key: &[u8; 32],
    content_nonce: [u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ContentAead::new(content_key.into())
        .encrypt(&Nonce::from(content_nonce), Payload { msg: payload, aad })
        .map_err(|_| CryptoError::Permanent)
}

/// Wraps the content key for one recipient with a fresh HPKE ephemeral key from `seed`.
fn wrap_content_key(
    recipient_public: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    content_key: &[u8; 32],
    seed: &[u8; 32],
) -> Staged<(Vec<u8>, Vec<u8>)> {
    let public = <Kem as KemTrait>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| RejectionStage::KeyValidation.with(CryptoError::InvalidKey))?;
    let mut rng = FixedRng::new(*seed);
    // An all-zero Diffie-Hellman result, from a low-order recipient key, fails here.
    let setup =
        setup_sender_with_rng::<HpkeAead, HkdfSha256, Kem>(&OpModeS::Base, &public, info, &mut rng);
    rng.finish()
        .map_err(|error| RejectionStage::BeforeObjectWrite.with(error))?;
    let (enc, mut context) =
        setup.map_err(|_| RejectionStage::KeyValidation.with(CryptoError::InvalidKey))?;
    let wrapped_key = context
        .seal(content_key, aad)
        .map_err(|_| RejectionStage::BeforeEncryption.with(CryptoError::Permanent))?;
    Ok((enc.to_bytes().to_vec(), wrapped_key))
}

fn assemble_envelope(
    protected: &[u8],
    ciphertext: &[u8],
    wrappers: Vec<Value>,
) -> Result<Vec<u8>, CryptoError> {
    let envelope = json!({
        "ciphertext": b64(ciphertext),
        "protected": b64(protected),
        "recipients": wrappers,
    });
    let bytes = canonicalize(&envelope).map_err(|_| CryptoError::Permanent)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::InvalidInput);
    }
    Ok(bytes)
}

fn has_duplicate_ids<'a>(mut ids: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::HashSet::new();
    ids.any(|id| !seen.insert(id))
}

impl<E: Entropy> EnvelopeCryptography for CryptoEngine<E> {
    fn seal(&self, request: &SealRequest<'_>) -> Result<SealedEnvelope, CryptoError> {
        seal_from_entropy(self, request).map_err(|rejection| rejection.error)
    }

    fn inspect(&self, envelope: &[u8]) -> Result<EnvelopeHeader, CryptoError> {
        inspect_staged(envelope).map_err(|rejection| rejection.error)
    }

    fn open(&self, envelope: &[u8], request: &OpenRequest<'_>) -> Result<Plaintext, CryptoError> {
        self.open_staged(envelope, request)
            .map(Plaintext::new)
            .map_err(|rejection| rejection.error)
    }
}

/// The parsed outer envelope: protected bytes, wrappers, and ciphertext, each shape-checked.
struct OuterEnvelope {
    protected: Vec<u8>,
    header: EnvelopeHeader,
    wrappers: Vec<([u8; 32], Vec<u8>)>,
    ciphertext: Vec<u8>,
    content_nonce: [u8; 12],
}

/// Validates the envelope's canonical form, protected header, and every wrapper's shape.
fn parse_outer(envelope: &[u8]) -> Staged<OuterEnvelope> {
    let header_error = RejectionStage::ProtectedHeader.with(CryptoError::InvalidInput);
    let envelope_value = parse_bounded_json(envelope, MAX_ENVELOPE_BYTES, MAX_ENVELOPE_DEPTH)
        .map_err(|_| header_error)?;
    if envelope_value.bytes() != envelope {
        return Err(header_error);
    }
    let object = envelope_value
        .value()
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or(header_error)?;
    let protected = decode_member(object.get("protected"), None).map_err(|_| header_error)?;
    let protected_document =
        parse_bounded_json(&protected, MAX_PROTECTED_BYTES, MAX_ENVELOPE_DEPTH)
            .map_err(|_| header_error)?;
    if protected_document.bytes() != protected {
        return Err(header_error);
    }
    let protected_value = protected_document.value();
    validate_protected(protected_value)?;

    let outer = object
        .get("recipients")
        .and_then(Value::as_array)
        .ok_or(header_error)?;
    if outer.len() != 2 {
        return Err(RejectionStage::ProtectedHashBinding.with(CryptoError::InvalidInput));
    }
    // Every wrapper is checked, not only the one this reader will select.
    let mut wrappers = Vec::with_capacity(outer.len());
    for wrapper in outer {
        let wrapper = wrapper
            .as_object()
            .filter(|wrapper| wrapper.len() == 2)
            .ok_or(RejectionStage::RecipientWrapper.with(CryptoError::InvalidInput))?;
        let enc = decode_fixed_member(wrapper.get("enc"))
            .map_err(|error| RejectionStage::KeyValidation.with(error))?;
        let wrapped_key = decode_member(wrapper.get("wrapped_key"), Some(48))
            .map_err(|error| RejectionStage::RecipientWrapper.with(error))?;
        wrappers.push((enc, wrapped_key));
    }
    let ciphertext = decode_member(object.get("ciphertext"), None)
        .map_err(|error| RejectionStage::ContentOpening.with(error))?;
    let content_nonce = <[u8; 12]>::try_from(
        decode_member(protected_value.get("content_nonce"), Some(12))
            .map_err(|_| header_error)?
            .as_slice(),
    )
    .map_err(|_| header_error)?;

    let sender = parse_header_key(
        protected_value.get("sender"),
        "signing_key_id",
        "sig-ed25519-",
    )
    .map_err(|_| header_error)?;
    let recipients = protected_value["recipients"]
        .as_array()
        .ok_or(header_error)?
        .iter()
        .map(|value| parse_header_key(Some(value), "encryption_key_id", "kem-x25519-"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| header_error)?;
    let document_id = DocumentId::new(
        protected_value["document_id"]
            .as_str()
            .ok_or(header_error)?,
    )
    .map_err(|_| header_error)?;
    let document_version = DocumentVersion::new(
        protected_value["document_version"]
            .as_u64()
            .ok_or(header_error)?,
    )
    .map_err(|_| header_error)?;
    let header = EnvelopeHeader {
        envelope_version: 1,
        protected_hash: sha256(&protected),
        document_id,
        document_version,
        schema_id: protected_value["schema_id"]
            .as_str()
            .ok_or(header_error)?
            .to_owned(),
        schema_digest: decode_fixed_member(protected_value.get("schema_digest"))
            .map_err(|_| header_error)?,
        sender,
        recipients,
    };
    Ok(OuterEnvelope {
        protected,
        header,
        wrappers,
        ciphertext,
        content_nonce,
    })
}

fn inspect_staged(envelope: &[u8]) -> Staged<EnvelopeHeader> {
    parse_outer(envelope).map(|outer| outer.header)
}

/// Seals with fresh operating-system randomness; nothing is produced when it is unavailable.
fn seal_from_entropy<E: Entropy>(
    engine: &CryptoEngine<E>,
    request: &SealRequest<'_>,
) -> Staged<SealedEnvelope> {
    let mut random = Zeroizing::new([0_u8; RANDOM_BYTES]);
    engine
        .entropy
        .fill(random.as_mut_slice())
        .map_err(|error| RejectionStage::BeforeObjectWrite.with(error))?;
    engine.seal_staged(request, &random)
}

impl<E> CryptoEngine<E> {
    /// Opens an envelope for one reader, in the fixed order of checks the conformance fixture
    /// names. Nothing is decrypted until the bindings, keys, and header have been checked.
    fn open_staged(&self, envelope: &[u8], request: &OpenRequest<'_>) -> Staged<Vec<u8>> {
        let outer = parse_outer(envelope)?;

        // The bindings must be the ones the committed header names, for the right purposes.
        let binding_error = RejectionStage::BindingValidation.with(CryptoError::InvalidKey);
        let trusted = request.header;
        if request.reader.purpose != KeyPurpose::DocumentEncryption
            || request.sender_signing.purpose != KeyPurpose::DocumentSigning
            || trusted.sender.wallet != request.sender_signing.wallet
            || trusted.sender.key_id != request.sender_signing.key_id
            || trusted.sender.binding_digest != request.sender_signing.binding_digest
        {
            return Err(binding_error);
        }
        let index = trusted
            .recipients
            .iter()
            .position(|recipient| {
                recipient.wallet == request.reader.wallet
                    && recipient.key_id == request.reader.key_id
                    && recipient.binding_digest == request.reader.binding_digest
            })
            .ok_or(binding_error)?;
        let material = self
            .encryption
            .iter()
            .find(|material| material.key_id == request.reader.key_id)
            .ok_or(binding_error)?;

        if !valid_ed25519_public(&request.sender_signing.public_key) {
            return Err(RejectionStage::KeyValidation.with(CryptoError::InvalidKey));
        }

        // The stored header must be exactly the committed one: same recipients, keys, and suite.
        if outer.header != *trusted {
            return Err(RejectionStage::ProtectedHashBinding.with(CryptoError::InvalidKey));
        }

        let (enc, wrapped_key) = outer
            .wrappers
            .get(index)
            .ok_or(RejectionStage::ProtectedHashBinding.with(CryptoError::InvalidInput))?;
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc)
            .map_err(|_| RejectionStage::KeyValidation.with(CryptoError::InvalidKey))?;
        let protected_hash = sha256(&outer.protected);
        let descriptor = recipient_descriptor_from_header(
            trusted
                .recipients
                .get(index)
                .ok_or(RejectionStage::ProtectedHashBinding.with(CryptoError::InvalidInput))?,
        )
        .map_err(|error| RejectionStage::ProtectedHashBinding.with(error))?;
        // An all-zero Diffie-Hellman result, from a low-order `enc`, fails here.
        let mut context = setup_receiver::<HpkeAead, HkdfSha256, Kem>(
            &OpModeR::Base,
            &material.private,
            &enc,
            &hpke_info(&protected_hash),
        )
        .map_err(|_| RejectionStage::KeyValidation.with(CryptoError::AuthenticationFailed))?;
        let content_key = Zeroizing::new(
            context
                .open(wrapped_key, &hpke_aad(&protected_hash, &descriptor))
                .map_err(|_| {
                    RejectionStage::RecipientWrapper.with(CryptoError::AuthenticationFailed)
                })?,
        );
        let cipher = ContentAead::new_from_slice(&content_key).map_err(|_| {
            RejectionStage::RecipientWrapper.with(CryptoError::AuthenticationFailed)
        })?;
        drop(content_key);
        let payload = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(outer.content_nonce),
                    Payload {
                        msg: &outer.ciphertext,
                        aad: &content_aad(&protected_hash),
                    },
                )
                .map_err(|_| {
                    RejectionStage::ContentOpening.with(CryptoError::AuthenticationFailed)
                })?,
        );
        open_payload(
            &payload,
            &protected_hash,
            &request.sender_signing.public_key,
        )
    }
}

fn recipient_descriptor_from_header(recipient: &HeaderKey) -> Result<Vec<u8>, CryptoError> {
    canonicalize(&json!({
        "binding_digest": b64(&recipient.binding_digest),
        "encryption_key_id": recipient.key_id,
        "wallet_id": recipient.wallet.as_str(),
    }))
    .map_err(|_| CryptoError::InvalidInput)
}

fn build_protected(
    request: &SealRequest<'_>,
    sorted_recipients: &[&VerifiedBinding; 2],
    content_nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let recipients = sorted_recipients
        .iter()
        .map(|binding| {
            json!({
                "binding_digest": b64(&binding.binding_digest),
                "encryption_key_id": binding.key_id,
                "wallet_id": binding.wallet.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "algorithms": {
            "canonicalization": "RFC8785",
            "content_aead": "ChaCha20Poly1305",
            "digest": "SHA-256",
            "hpke_aead_id": 3,
            "hpke_kdf_id": 1,
            "hpke_kem_id": 32,
            "hpke_mode": 0,
            "signature": "Ed25519",
        },
        "content_nonce": b64(&content_nonce),
        "document_id": request.document_id.as_str(),
        "document_version": request.document_version.get(),
        "envelope_version": 1,
        "operation": "send-copy",
        "recipients": recipients,
        "request_nonce": b64(request.request_nonce.as_bytes()),
        "schema_digest": b64(&request.schema_digest),
        "schema_id": request.schema_id,
        "sender": {
            "binding_digest": b64(&request.sender_signing.binding_digest),
            "signing_key_id": request.sender_signing.key_id,
            "wallet_id": request.sender_signing.wallet.as_str(),
        },
    });
    let bytes = canonicalize(&value).map_err(|_| CryptoError::InvalidInput)?;
    if bytes.len() > MAX_PROTECTED_BYTES {
        return Err(CryptoError::InvalidInput);
    }
    Ok(bytes)
}

fn parse_header_key(
    value: Option<&Value>,
    id_member: &str,
    id_prefix: &str,
) -> Result<HeaderKey, CryptoError> {
    let object = value
        .and_then(Value::as_object)
        .filter(|object| object.len() == 3)
        .ok_or(CryptoError::InvalidInput)?;
    let wallet = WalletId::new(
        object
            .get("wallet_id")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidInput)?,
    )
    .map_err(|_| CryptoError::InvalidInput)?;
    let key_id = object
        .get(id_member)
        .and_then(Value::as_str)
        .filter(|id| valid_derived_key_id(Some(id), id_prefix))
        .ok_or(CryptoError::InvalidInput)?
        .to_owned();
    Ok(HeaderKey {
        wallet,
        key_id,
        binding_digest: decode_fixed_member(object.get("binding_digest"))?,
    })
}

fn decode_fixed_member(value: Option<&Value>) -> Result<[u8; 32], CryptoError> {
    decode_member(value, Some(32))?
        .try_into()
        .map_err(|_| CryptoError::InvalidInput)
}

/// Checks every protected-header member. An unknown suite or version is refused outright, with
/// no fallback; a malformed recipient set breaks the binding to the committed recipients.
fn validate_protected(value: &Value) -> Staged<()> {
    let header_error = RejectionStage::ProtectedHeader.with(CryptoError::InvalidInput);
    let recipient_error = RejectionStage::ProtectedHashBinding.with(CryptoError::InvalidInput);
    let object = value
        .as_object()
        .filter(|object| object.len() == 11)
        .ok_or(header_error)?;
    let algorithms = object
        .get("algorithms")
        .and_then(Value::as_object)
        .filter(|algorithms| algorithms.len() == 8)
        .ok_or(header_error)?;
    let expected = [
        ("canonicalization", json!("RFC8785")),
        ("content_aead", json!("ChaCha20Poly1305")),
        ("digest", json!("SHA-256")),
        ("hpke_aead_id", json!(3)),
        ("hpke_kdf_id", json!(1)),
        ("hpke_kem_id", json!(32)),
        ("hpke_mode", json!(0)),
        ("signature", json!("Ed25519")),
    ];
    if expected
        .iter()
        .any(|(key, expected)| algorithms.get(*key) != Some(expected))
        || object.get("envelope_version") != Some(&json!(1))
        || object.get("operation") != Some(&json!("send-copy"))
    {
        return Err(RejectionStage::ProtectedHeader.with(CryptoError::UnsupportedSuite));
    }

    decode_member(object.get("content_nonce"), Some(12)).map_err(|_| header_error)?;
    decode_member(object.get("request_nonce"), Some(16)).map_err(|_| header_error)?;
    let document_id = object
        .get("document_id")
        .and_then(Value::as_str)
        .ok_or(header_error)?;
    DocumentId::new(document_id).map_err(|_| header_error)?;
    if object
        .get("document_version")
        .and_then(Value::as_u64)
        .is_none_or(|version| version == 0 || version > 9_007_199_254_740_991)
        || object.get("schema_id").and_then(Value::as_str)
            != Some("urn:docchain:schema:service-application:1.0.0")
    {
        return Err(header_error);
    }
    decode_member(object.get("schema_digest"), Some(32)).map_err(|_| header_error)?;

    let sender = object
        .get("sender")
        .and_then(Value::as_object)
        .filter(|sender| sender.len() == 3)
        .ok_or(header_error)?;
    let sender_wallet = sender
        .get("wallet_id")
        .and_then(Value::as_str)
        .ok_or(header_error)?;
    WalletId::new(sender_wallet).map_err(|_| header_error)?;
    decode_member(sender.get("binding_digest"), Some(32)).map_err(|_| header_error)?;
    if !valid_derived_key_id(
        sender.get("signing_key_id").and_then(Value::as_str),
        "sig-ed25519-",
    ) {
        return Err(header_error);
    }

    let recipients = object
        .get("recipients")
        .and_then(Value::as_array)
        .ok_or(header_error)?;
    if recipients.len() != 2 {
        return Err(recipient_error);
    }
    let mut prior: Option<(&str, &str)> = None;
    let mut includes_sender = false;
    for recipient in recipients {
        let recipient = recipient
            .as_object()
            .filter(|recipient| recipient.len() == 3)
            .ok_or(header_error)?;
        let wallet = recipient
            .get("wallet_id")
            .and_then(Value::as_str)
            .ok_or(header_error)?;
        WalletId::new(wallet).map_err(|_| header_error)?;
        let key_id = recipient
            .get("encryption_key_id")
            .and_then(Value::as_str)
            .ok_or(header_error)?;
        if !valid_derived_key_id(Some(key_id), "kem-x25519-") {
            return Err(header_error);
        }
        decode_member(recipient.get("binding_digest"), Some(32)).map_err(|_| header_error)?;
        if prior.is_some_and(|previous| {
            previous
                .0
                .as_bytes()
                .cmp(wallet.as_bytes())
                .then_with(|| previous.1.as_bytes().cmp(key_id.as_bytes()))
                .is_ge()
        }) {
            return Err(recipient_error);
        }
        prior = Some((wallet, key_id));
        includes_sender |= wallet == sender_wallet;
    }
    if !includes_sender {
        return Err(recipient_error);
    }
    Ok(())
}

fn valid_derived_key_id(value: Option<&str>, prefix: &str) -> bool {
    value
        .and_then(|value| value.strip_prefix(prefix))
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .is_some_and(|bytes| bytes.len() == 32)
}

/// Checks the payload's exact length, then its digest and signature, and only then parses the
/// document it carries.
fn open_payload(
    payload: &[u8],
    protected_hash: &[u8; 32],
    signing_public: &[u8; 32],
) -> Staged<Vec<u8>> {
    let length_error = RejectionStage::PayloadLength.with(CryptoError::AuthenticationFailed);
    let verification_error = RejectionStage::Verification.with(CryptoError::AuthenticationFailed);
    if payload.get(0..4) != Some(b"DCP1".as_slice()) {
        return Err(length_error);
    }
    let length_bytes =
        <[u8; 4]>::try_from(payload.get(4..8).ok_or(length_error)?).map_err(|_| length_error)?;
    let document_length =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| length_error)?;
    let document_end = 8_usize.checked_add(document_length).ok_or(length_error)?;
    let digest_end = document_end.checked_add(32).ok_or(length_error)?;
    if digest_end.checked_add(64) != Some(payload.len()) {
        return Err(length_error);
    }
    let document = payload.get(8..document_end).ok_or(verification_error)?;
    let digest = <[u8; 32]>::try_from(
        payload
            .get(document_end..digest_end)
            .ok_or(verification_error)?,
    )
    .map_err(|_| verification_error)?;
    let signature = <[u8; 64]>::try_from(payload.get(digest_end..).ok_or(verification_error)?)
        .map_err(|_| verification_error)?;
    if sha256(document) != digest {
        return Err(verification_error);
    }
    let signature_input = Zeroizing::new(
        [
            SIGNATURE_LABEL,
            protected_hash.as_slice(),
            digest.as_slice(),
        ]
        .concat(),
    );
    strict_verify(signing_public, &signature_input, signature).map_err(|_| verification_error)?;

    let strict_error = RejectionStage::StrictParse.with(CryptoError::AuthenticationFailed);
    let parsed = parse_document(document).map_err(|_| strict_error)?;
    if parsed.bytes() != document {
        return Err(strict_error);
    }
    Ok(document.to_vec())
}

pub(crate) fn strict_verify(
    public: &[u8; 32],
    message: &[u8],
    signature: [u8; 64],
) -> Result<(), CryptoError> {
    if !canonical_edwards(public)
        || small_order_edwards(public)
        || !canonical_edwards(
            signature[0..32]
                .try_into()
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        )
        || !scalar_is_canonical(
            signature[32..64]
                .try_into()
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        )
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let verifying_key =
        VerificationKey::try_from(public.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
    let signature = Signature::from(signature);
    verifying_key
        .verify(&signature, message)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn small_order_edwards(public: &[u8; 32]) -> bool {
    const ZERO: [u8; 32] = [0; 32];
    const IDENTITY: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const ORDER_TWO: [u8; 32] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const ORDER_EIGHT_A: [u8; 32] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4d, 0x58, 0xd0, 0x53, 0xf8, 0x4a,
        0x03, 0x7a,
    ];
    const ORDER_EIGHT_B: [u8; 32] = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ];
    let mut without_sign = *public;
    without_sign[31] &= 0x7f;
    without_sign == ZERO
        || without_sign == IDENTITY
        || without_sign == ORDER_TWO
        || without_sign == ORDER_EIGHT_A
        || without_sign == ORDER_EIGHT_B
}

pub(crate) fn valid_ed25519_public(public: &[u8; 32]) -> bool {
    canonical_edwards(public)
        && !small_order_edwards(public)
        && VerificationKey::try_from(public.as_slice()).is_ok()
}

fn canonical_edwards(encoded: &[u8; 32]) -> bool {
    let mut y = *encoded;
    y[31] &= 0x7f;
    let mut modulus = [0xff_u8; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    little_endian_less(&y, &modulus) && encoded.iter().any(|byte| *byte != 0)
}

fn scalar_is_canonical(scalar: &[u8; 32]) -> bool {
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    little_endian_less(scalar, &ORDER)
}

fn little_endian_less(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .rev()
        .zip(right.iter().rev())
        .find_map(|(left, right)| (left != right).then_some(left < right))
        .unwrap_or(false)
}

fn decode_member(
    value: Option<&Value>,
    expected_length: Option<usize>,
) -> Result<Vec<u8>, CryptoError> {
    let encoded = value
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidInput)?;
    if encoded.contains('=') || encoded.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(CryptoError::InvalidInput);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CryptoError::InvalidInput)?;
    if b64(&decoded) != encoded || expected_length.is_some_and(|length| decoded.len() != length) {
        return Err(CryptoError::InvalidInput);
    }
    Ok(decoded)
}

fn b64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Serves one HPKE ephemeral seed, exactly once, for one 32-byte request.
///
/// `hpke` takes an infallible generator, so a request this generator cannot serve is recorded
/// rather than returned: the destination is left untouched, never filled with zeros or any other
/// stand-in, and [`FixedRng::finish`] reports the failure before the caller uses the result.
struct FixedRng {
    bytes: Zeroizing<[u8; 32]>,
    served: bool,
    failed: bool,
}

impl FixedRng {
    fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            served: false,
            failed: false,
        }
    }

    /// Serves the seed, or fails for any second request or any request of another length.
    fn take(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        if self.served || self.failed || destination.len() != self.bytes.len() {
            self.failed = true;
            return Err(CryptoError::EntropyExhausted);
        }
        destination.copy_from_slice(self.bytes.as_slice());
        self.bytes.zeroize();
        self.served = true;
        Ok(())
    }

    /// Reports whether every request was served from the seed.
    ///
    /// # Errors
    ///
    /// [`CryptoError::EntropyExhausted`] after any request the seed could not serve.
    fn finish(&self) -> Result<(), CryptoError> {
        if self.failed {
            Err(CryptoError::EntropyExhausted)
        } else {
            Ok(())
        }
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        // A refused request is recorded in `failed`, which `finish` reports.
        let _ = self.take(destination);
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct DesignVector {
    pub schema_bytes: String,
    pub schema_digest: String,
    pub document_bytes: String,
    pub document_digest: String,
    pub registry_public_key: String,
    pub registry_key_id: String,
    pub sender_public_key: String,
    pub sender_key_id: String,
    pub encryption_public_keys: [String; 2],
    pub encryption_key_ids: [String; 2],
    pub binding_records: [String; 3],
    pub binding_digests: [String; 3],
    pub signature_input: String,
    pub protected_hash: String,
    pub signature: String,
    pub payload: String,
    pub content_aad: String,
    pub content_ciphertext: String,
    pub hpke_info: String,
    pub recipient_descriptors: [String; 2],
    pub hpke_aads: [String; 2],
    pub encapsulated_keys: [String; 2],
    pub wrapped_keys: [String; 2],
    pub commitment: String,
    pub protected_bytes: String,
    pub envelope_bytes: String,
}

/// Fixed-key material for the normative version 1 conformance vector.
///
/// The design vector and the negative mutation suite share this material so both
/// exercise the same bytes the envelope contract pins.
#[cfg(any(test, feature = "test-support"))]
struct VectorContext {
    engine: CryptoEngine<FailingEntropy>,
    document: Vec<u8>,
    document_id: DocumentId,
    document_version: DocumentVersion,
    request_nonce: RequestNonce,
    schema_digest: [u8; 32],
    sender_signing: VerifiedBinding,
    recipients: [VerifiedBinding; 2],
    random: Zeroizing<[u8; RANDOM_BYTES]>,
    registry_public: [u8; 32],
    registry_key_id: String,
    binding_records: [Vec<u8>; 3],
}

#[cfg(any(test, feature = "test-support"))]
impl VectorContext {
    fn request(&self) -> SealRequest<'_> {
        SealRequest {
            canonical_document: &self.document,
            document_id: &self.document_id,
            document_version: self.document_version,
            request_nonce: &self.request_nonce,
            schema_id: "urn:docchain:schema:service-application:1.0.0",
            schema_digest: self.schema_digest,
            sender_signing: &self.sender_signing,
            recipients: [&self.recipients[0], &self.recipients[1]],
        }
    }
}

/// `start, start + 1, ...`, the fixture's way of writing invented key material.
#[cfg(any(test, feature = "test-support"))]
fn sequential<const N: usize>(start: u8) -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = start
            .checked_add(u8::try_from(index).map_err(|_| CryptoError::Permanent)?)
            .ok_or(CryptoError::Permanent)?;
    }
    Ok(bytes)
}

/// The fixture registry authority: its signing key, public key, and key ID.
#[cfg(any(test, feature = "test-support"))]
fn registry_authority() -> Result<(SigningKey, [u8; 32], String), CryptoError> {
    let signing = SigningKey::from(sequential(0)?);
    let public: [u8; 32] = VerificationKey::from(&signing).into();
    let key_id = format!("reg-ed25519-{}", b64(&sha256(&public)));
    Ok((signing, public, key_id))
}

#[cfg(any(test, feature = "test-support"))]
fn vector_context() -> Result<VectorContext, CryptoError> {
    let sender = WalletId::new("wal_0000000000000001").map_err(|_| CryptoError::Permanent)?;
    let recipient = WalletId::new("wal_0000000000000002").map_err(|_| CryptoError::Permanent)?;
    let (registry_signing, registry_public, registry_key_id) = registry_authority()?;
    let sign_seed = sequential(0x20)?;
    let signing = SigningKey::from(sign_seed);
    let signing_public: [u8; 32] = VerificationKey::from(&signing).into();
    let signing_key_id = "sig-ed25519-JPbtasv-EAnAMNfKVnwzykgwkRSYI2tVYabIKr7F3ig".to_owned();
    let (sender_ikm, sender_encryption) = vector_encryption(
        sender.clone(),
        0x40,
        "kem-x25519-2N75snd6-zKUUkrlldIKhdTGDJeNDMKF_knhwUKbxLs",
        "0WejQt77M7UEGaEarIy6U0kzi3nHZzfFz4qrI2beg2w",
    )?;
    let (recipient_ikm, recipient_encryption) = vector_encryption(
        recipient.clone(),
        0x60,
        "kem-x25519-MJEVQM_yguYS9Yb3lGJfNCgI4P6ZbfFFgiISGzfabjg",
        "UTCxOJflyJeuZmVrzKkGfRY6_fHSx2N3W_u68DbPSZ8",
    )?;
    let signing_binding = vector_binding_record(
        &registry_key_id,
        &registry_signing,
        VectorBinding {
            sequence: 1,
            wallet: &sender,
            key_id: &signing_key_id,
            purpose: "document-signing",
            algorithm: "Ed25519",
            public_key: &signing_public,
            expected_digest: Some("YIQjxw1FoVmcfctxUTy_I_g1DTvkeaXoA0-XqlKIXxA"),
        },
    )?;
    let sender_encryption_binding = vector_binding_record(
        &registry_key_id,
        &registry_signing,
        VectorBinding {
            sequence: 2,
            wallet: &sender,
            key_id: &sender_encryption.key_id,
            purpose: "document-encryption",
            algorithm: "X25519",
            public_key: &sender_encryption.public_key,
            expected_digest: Some("0WejQt77M7UEGaEarIy6U0kzi3nHZzfFz4qrI2beg2w"),
        },
    )?;
    let recipient_encryption_binding = vector_binding_record(
        &registry_key_id,
        &registry_signing,
        VectorBinding {
            sequence: 3,
            wallet: &recipient,
            key_id: &recipient_encryption.key_id,
            purpose: "document-encryption",
            algorithm: "X25519",
            public_key: &recipient_encryption.public_key,
            expected_digest: Some("UTCxOJflyJeuZmVrzKkGfRY6_fHSx2N3W_u68DbPSZ8"),
        },
    )?;
    let sender_signing = VerifiedBinding {
        wallet: sender,
        purpose: KeyPurpose::DocumentSigning,
        key_id: signing_key_id,
        public_key: signing_public,
        binding_digest: sha256(&signing_binding),
        sequence: 1,
    };
    let engine = CryptoEngine::from_material(
        vec![sign_seed],
        vec![sender_ikm, recipient_ikm],
        FailingEntropy,
    )?;
    let mut random = Zeroizing::new([0_u8; RANDOM_BYTES]);
    for (range, start) in [
        (0..32, 0xc0),
        (32..44, 0xe0),
        (44..76, 0x80),
        (76..108, 0xa0),
    ] {
        let block = random.get_mut(range).ok_or(CryptoError::Permanent)?;
        let values: [u8; 32] = sequential(start)?;
        for (byte, value) in block.iter_mut().zip(values) {
            *byte = value;
        }
    }
    let schema = parse_document(include_bytes!(
        "../../../schemas/service-application/1.0.0.schema.json"
    ))
    .map_err(|_| CryptoError::Permanent)?;
    let document = parse_document(include_bytes!(
        "../../../schemas/service-application/example.json"
    ))
    .map_err(|_| CryptoError::Permanent)?;
    Ok(VectorContext {
        engine,
        document: document.bytes().to_vec(),
        document_id: DocumentId::new("doc_0000000000000001").map_err(|_| CryptoError::Permanent)?,
        document_version: DocumentVersion::new(1).map_err(|_| CryptoError::Permanent)?,
        request_nonce: RequestNonce::new(sequential(0xf0)?),
        schema_digest: sha256(schema.bytes()),
        sender_signing,
        recipients: [sender_encryption, recipient_encryption],
        random,
        registry_public,
        registry_key_id,
        binding_records: [
            signing_binding,
            sender_encryption_binding,
            recipient_encryption_binding,
        ],
    })
}

#[cfg(any(test, feature = "test-support"))]
pub fn run_design_vector() -> Result<DesignVector, CryptoError> {
    let context = vector_context()?;
    let request = context.request();
    let signing = &context.engine.signing[0].1;
    let signing_public: [u8; 32] = VerificationKey::from(signing).into();
    let recipients = sorted_recipients(request.recipients);
    let content_key =
        <[u8; 32]>::try_from(&context.random[0..32]).map_err(|_| CryptoError::Permanent)?;
    let content_nonce =
        <[u8; 12]>::try_from(&context.random[32..44]).map_err(|_| CryptoError::Permanent)?;
    let protected = build_protected(&request, &recipients, content_nonce)?;
    let protected_hash = sha256(&protected);
    let document_digest = sha256(&context.document);
    let signature_input = [
        SIGNATURE_LABEL,
        protected_hash.as_slice(),
        document_digest.as_slice(),
    ]
    .concat();
    let signature: [u8; 64] = signing.sign(&signature_input).into();
    let payload = signed_payload(signing, &protected_hash, &context.document)?;
    let content_aad = content_aad(&protected_hash);
    let content_ciphertext = encrypt_content(&payload, &content_key, content_nonce, &content_aad)?;

    let hpke_info = hpke_info(&protected_hash);
    let mut recipient_descriptors = Vec::with_capacity(2);
    let mut hpke_aads = Vec::with_capacity(2);
    let mut encapsulated_keys = Vec::with_capacity(2);
    let mut wrapped_keys = Vec::with_capacity(2);
    for (index, binding) in recipients.iter().enumerate() {
        let descriptor = recipient_descriptor(binding)?;
        let aad = hpke_aad(&protected_hash, &descriptor);
        let offset = 44 + index * 32;
        let seed = <[u8; 32]>::try_from(
            context
                .random
                .get(offset..offset + 32)
                .ok_or(CryptoError::Permanent)?,
        )
        .map_err(|_| CryptoError::Permanent)?;
        let (enc, wrapped_key) =
            wrap_content_key(&binding.public_key, &hpke_info, &aad, &content_key, &seed)
                .map_err(|rejection| rejection.error)?;
        recipient_descriptors
            .push(String::from_utf8(descriptor).map_err(|_| CryptoError::Permanent)?);
        hpke_aads.push(b64(&aad));
        encapsulated_keys.push(b64(&enc));
        wrapped_keys.push(b64(&wrapped_key));
    }

    let sealed = context
        .engine
        .seal_staged(&context.request(), &context.random)
        .map_err(|rejection| rejection.error)?;
    let schema = parse_document(include_bytes!(
        "../../../schemas/service-application/1.0.0.schema.json"
    ))
    .map_err(|_| CryptoError::Permanent)?;
    Ok(DesignVector {
        schema_bytes: String::from_utf8(schema.bytes().to_vec())
            .map_err(|_| CryptoError::Permanent)?,
        schema_digest: b64(&sha256(schema.bytes())),
        document_bytes: String::from_utf8(context.document.clone())
            .map_err(|_| CryptoError::Permanent)?,
        document_digest: b64(&document_digest),
        registry_public_key: b64(&context.registry_public),
        registry_key_id: context.registry_key_id.clone(),
        sender_public_key: b64(&signing_public),
        sender_key_id: context.sender_signing.key_id.clone(),
        encryption_public_keys: context
            .recipients
            .each_ref()
            .map(|binding| b64(&binding.public_key)),
        encryption_key_ids: context
            .recipients
            .each_ref()
            .map(|binding| binding.key_id.clone()),
        binding_records: {
            let [signing_record, sender_record, recipient_record] = context.binding_records.clone();
            [
                String::from_utf8(signing_record).map_err(|_| CryptoError::Permanent)?,
                String::from_utf8(sender_record).map_err(|_| CryptoError::Permanent)?,
                String::from_utf8(recipient_record).map_err(|_| CryptoError::Permanent)?,
            ]
        },
        binding_digests: [
            b64(&context.sender_signing.binding_digest),
            b64(&context.recipients[0].binding_digest),
            b64(&context.recipients[1].binding_digest),
        ],
        signature_input: b64(&signature_input),
        protected_hash: b64(&protected_hash),
        signature: b64(&signature),
        payload: b64(&payload),
        content_aad: b64(&content_aad),
        content_ciphertext: b64(&content_ciphertext),
        hpke_info: b64(&hpke_info),
        recipient_descriptors: recipient_descriptors
            .try_into()
            .map_err(|_| CryptoError::Permanent)?,
        hpke_aads: hpke_aads.try_into().map_err(|_| CryptoError::Permanent)?,
        encapsulated_keys: encapsulated_keys
            .try_into()
            .map_err(|_| CryptoError::Permanent)?,
        wrapped_keys: wrapped_keys
            .try_into()
            .map_err(|_| CryptoError::Permanent)?,
        commitment: b64(&sealed.commitment),
        protected_bytes: String::from_utf8(protected).map_err(|_| CryptoError::Permanent)?,
        envelope_bytes: String::from_utf8(sealed.bytes).map_err(|_| CryptoError::Permanent)?,
    })
}

#[cfg(any(test, feature = "test-support"))]
struct VectorBinding<'a> {
    sequence: u64,
    wallet: &'a WalletId,
    key_id: &'a str,
    purpose: &'a str,
    algorithm: &'a str,
    public_key: &'a [u8],
    /// The fixture's digest for this record; `None` for records the fixture does not contain.
    expected_digest: Option<&'a str>,
}

#[cfg(any(test, feature = "test-support"))]
fn vector_binding_record(
    authority_key_id: &str,
    authority: &SigningKey,
    binding: VectorBinding<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let body = json!({
        "algorithm": binding.algorithm,
        "authority_key_id": authority_key_id,
        "key_id": binding.key_id,
        "not_before": "2026-09-19T00:00:00Z",
        "public_key": b64(binding.public_key),
        "purpose": binding.purpose,
        "registry_sequence": binding.sequence,
        "state": "active",
        "wallet_id": binding.wallet.as_str(),
    });
    let body_bytes = canonicalize(&body).map_err(|_| CryptoError::Permanent)?;
    let mut signature_input = Vec::with_capacity(25 + 32);
    signature_input.extend_from_slice(b"docchain/key-binding/v1\0");
    signature_input.extend_from_slice(&sha256(&body_bytes));
    let signature: [u8; 64] = authority.sign(&signature_input).into();
    let record = canonicalize(&json!({
        "body": body,
        "signature": b64(&signature),
    }))
    .map_err(|_| CryptoError::Permanent)?;
    if binding
        .expected_digest
        .is_some_and(|expected| b64(&sha256(&record)) != expected)
    {
        return Err(CryptoError::Permanent);
    }
    Ok(record)
}

#[cfg(any(test, feature = "test-support"))]
fn vector_encryption(
    wallet: WalletId,
    start: u8,
    expected_key_id: &str,
    binding: &str,
) -> Result<([u8; 32], VerifiedBinding), CryptoError> {
    let ikm = sequential(start)?;
    let (key_id, public_key) = encryption_public(&ikm)?;
    if key_id != expected_key_id {
        return Err(CryptoError::Permanent);
    }
    Ok((
        ikm,
        VerifiedBinding {
            wallet,
            purpose: KeyPurpose::DocumentEncryption,
            key_id,
            public_key,
            binding_digest: decode_fixed(binding)?,
            sequence: 0,
        },
    ))
}

/// The derived key ID and public key for an RFC 9180 X25519 key-generation input.
#[cfg(any(test, feature = "test-support"))]
fn encryption_public(ikm: &[u8; 32]) -> Result<(String, [u8; 32]), CryptoError> {
    let (private, public) = Kem::derive_keypair(ikm);
    drop(private);
    let public_bytes = public.to_bytes();
    let public_key: [u8; 32] = public_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Permanent)?;
    Ok((
        format!("kem-x25519-{}", b64(&sha256(&public_key))),
        public_key,
    ))
}

#[cfg(any(test, feature = "test-support"))]
fn decode_fixed(value: &str) -> Result<[u8; 32], CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::Permanent)?
        .try_into()
        .map_err(|_| CryptoError::Permanent)
}

/// An invented third wallet, `wal_0000000000000003`, whose ID sorts after both vector wallets.
///
/// Its two bindings are signed by the fixture registry authority, with sequences 4 and 5, but they
/// are not part of the conformance vector.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct ThirdWallet {
    pub(crate) signing_seed: [u8; 32],
    pub(crate) encryption_ikm: [u8; 32],
    /// Canonical signing and encryption binding records, in registry order.
    #[cfg_attr(
        not(feature = "test-support"),
        expect(dead_code, reason = "only the test-support harness registers them")
    )]
    pub(crate) binding_records: [Vec<u8>; 2],
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the envelope unit tests seal with it")
    )]
    pub(crate) signing: VerifiedBinding,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only the envelope unit tests seal with it")
    )]
    pub(crate) encryption: VerifiedBinding,
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn third_wallet() -> Result<ThirdWallet, CryptoError> {
    let wallet = WalletId::new("wal_0000000000000003").map_err(|_| CryptoError::Permanent)?;
    let (authority, _, authority_key_id) = registry_authority()?;
    let signing_seed = sequential(0x10)?;
    let signing_public: [u8; 32] = VerificationKey::from(&SigningKey::from(signing_seed)).into();
    let signing_key_id = format!("sig-ed25519-{}", b64(&sha256(&signing_public)));
    let encryption_ikm = sequential(0x70)?;
    let (encryption_key_id, encryption_public_key) = encryption_public(&encryption_ikm)?;
    let signing_record = vector_binding_record(
        &authority_key_id,
        &authority,
        VectorBinding {
            sequence: 4,
            wallet: &wallet,
            key_id: &signing_key_id,
            purpose: "document-signing",
            algorithm: "Ed25519",
            public_key: &signing_public,
            expected_digest: None,
        },
    )?;
    let encryption_record = vector_binding_record(
        &authority_key_id,
        &authority,
        VectorBinding {
            sequence: 5,
            wallet: &wallet,
            key_id: &encryption_key_id,
            purpose: "document-encryption",
            algorithm: "X25519",
            public_key: &encryption_public_key,
            expected_digest: None,
        },
    )?;
    Ok(ThirdWallet {
        signing_seed,
        encryption_ikm,
        signing: VerifiedBinding {
            wallet: wallet.clone(),
            purpose: KeyPurpose::DocumentSigning,
            key_id: signing_key_id,
            public_key: signing_public,
            binding_digest: sha256(&signing_record),
            sequence: 4,
        },
        encryption: VerifiedBinding {
            wallet,
            purpose: KeyPurpose::DocumentEncryption,
            key_id: encryption_key_id,
            public_key: encryption_public_key,
            binding_digest: sha256(&encryption_record),
            sequence: 5,
        },
        binding_records: [signing_record, encryption_record],
    })
}

/// Signs a binding body with the fixture registry authority, as [`third_wallet`]'s records are
/// signed, and returns the canonical record.
#[cfg(feature = "test-support")]
pub(crate) fn authority_signed_record(body: &Value) -> Result<Vec<u8>, CryptoError> {
    let (authority, _, _) = registry_authority()?;
    let body_bytes = canonicalize(body).map_err(|_| CryptoError::Permanent)?;
    let mut signature_input = Vec::with_capacity(25 + 32);
    signature_input.extend_from_slice(b"docchain/key-binding/v1\0");
    signature_input.extend_from_slice(&sha256(&body_bytes));
    let signature: [u8; 64] = authority.sign(&signature_input).into();
    canonicalize(&json!({"body": body, "signature": b64(&signature)}))
        .map_err(|_| CryptoError::Permanent)
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    N01,
    N02,
    N03,
    N04,
    N05,
    N06,
    N07,
    N08,
    N09,
    N10,
    N11,
    N12,
    N13,
}

#[cfg(any(test, feature = "test-support"))]
impl Mutation {
    pub const ALL: [Self; 13] = [
        Self::N01,
        Self::N02,
        Self::N03,
        Self::N04,
        Self::N05,
        Self::N06,
        Self::N07,
        Self::N08,
        Self::N09,
        Self::N10,
        Self::N11,
        Self::N12,
        Self::N13,
    ];

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::N01 => "N01",
            Self::N02 => "N02",
            Self::N03 => "N03",
            Self::N04 => "N04",
            Self::N05 => "N05",
            Self::N06 => "N06",
            Self::N07 => "N07",
            Self::N08 => "N08",
            Self::N09 => "N09",
            Self::N10 => "N10",
            Self::N11 => "N11",
            Self::N12 => "N12",
            Self::N13 => "N13",
        }
    }
}

/// The observed result of one sub-mutation of a fixture mutation ID.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegativeCase {
    /// What this sub-mutation changes.
    pub case: &'static str,
    /// True when the operation failed and returned no plaintext and no sealed envelope.
    pub rejected: bool,
    /// The fixture `rejection_stage` of the check that rejected it; `None` when the case was
    /// accepted, or for replay, which the exchange store rejects rather than the envelope.
    pub stage: Option<&'static str>,
}

/// `Ok(())` when accepted; otherwise the rejection, with the stage when a staged check made it.
#[cfg(any(test, feature = "test-support"))]
type CaseOutcome = Result<(), Option<Rejection>>;

#[cfg(any(test, feature = "test-support"))]
fn outcome<T>(result: Staged<T>) -> CaseOutcome {
    result.map(|_| ()).map_err(Some)
}

/// A send-path gate outside this adapter: `stage` when it rejects `mutated` but accepts the
/// unmutated `control`, so the rejection is attributable to the mutation alone.
#[cfg(any(test, feature = "test-support"))]
fn gate<T, E>(stage: RejectionStage, control: Result<T, E>, mutated: Result<T, E>) -> CaseOutcome {
    match (control, mutated) {
        (Ok(_), Err(_)) => Err(Some(stage.with(CryptoError::InvalidInput))),
        _ => Ok(()),
    }
}

/// The normative envelope, its committed header, and the conformance material that made it.
#[cfg(any(test, feature = "test-support"))]
struct Fixture {
    context: VectorContext,
    bytes: Vec<u8>,
    header: EnvelopeHeader,
    protected: Vec<u8>,
}

#[cfg(any(test, feature = "test-support"))]
impl Fixture {
    /// Seals the vector and proves both participants open it before any mutation.
    fn new() -> Result<Self, CryptoError> {
        let context = vector_context()?;
        let bytes = context
            .engine
            .seal_staged(&context.request(), &context.random)
            .map_err(|rejection| rejection.error)?
            .bytes;
        let outer = parse_outer(&bytes).map_err(|rejection| rejection.error)?;
        let fixture = Self {
            context,
            header: outer.header,
            protected: outer.protected,
            bytes,
        };
        for reader in &fixture.context.recipients {
            fixture
                .open_as(
                    &fixture.bytes,
                    &fixture.header,
                    reader,
                    &fixture.context.sender_signing,
                )
                .map_err(|rejection| rejection.error)?;
        }
        Ok(fixture)
    }

    fn open_as(
        &self,
        bytes: &[u8],
        header: &EnvelopeHeader,
        reader: &VerifiedBinding,
        sender_signing: &VerifiedBinding,
    ) -> Staged<Vec<u8>> {
        self.context.engine.open_staged(
            bytes,
            &OpenRequest {
                header,
                reader,
                sender_signing,
            },
        )
    }

    /// Opens as the vector recipient against the committed header.
    fn open(&self, bytes: &[u8]) -> CaseOutcome {
        outcome(self.open_as(
            bytes,
            &self.header,
            &self.context.recipients[1],
            &self.context.sender_signing,
        ))
    }

    /// Opens with substituted bindings.
    fn open_with(&self, reader: &VerifiedBinding, sender_signing: &VerifiedBinding) -> CaseOutcome {
        outcome(self.open_as(&self.bytes, &self.header, reader, sender_signing))
    }

    /// The canonical envelope after `mutate`, which must change it.
    fn edit(&self, mutate: impl FnOnce(&mut Value) -> Option<()>) -> Result<Vec<u8>, CryptoError> {
        let mut value = parse_document(&self.bytes)
            .map_err(|_| CryptoError::Permanent)?
            .value()
            .clone();
        mutate(&mut value).ok_or(CryptoError::Permanent)?;
        let mutated = canonicalize(&value).map_err(|_| CryptoError::Permanent)?;
        if mutated == self.bytes {
            return Err(CryptoError::Permanent);
        }
        Ok(mutated)
    }

    /// The protected header after `mutate`, canonical and not re-sealed.
    fn protected_with(
        &self,
        mutate: impl FnOnce(&mut Value) -> Option<()>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut value = parse_document(&self.protected)
            .map_err(|_| CryptoError::Permanent)?
            .value()
            .clone();
        mutate(&mut value).ok_or(CryptoError::Permanent)?;
        let protected = canonicalize(&value).map_err(|_| CryptoError::Permanent)?;
        if protected == self.protected {
            return Err(CryptoError::Permanent);
        }
        Ok(protected)
    }

    /// The envelope with only its protected member replaced.
    fn edit_protected(
        &self,
        mutate: impl FnOnce(&mut Value) -> Option<()>,
    ) -> Result<Vec<u8>, CryptoError> {
        let protected = self.protected_with(mutate)?;
        self.edit(|envelope| {
            *envelope.get_mut("protected")? = json!(b64(&protected));
            Some(())
        })
    }

    /// The vector's signed payload.
    fn payload(&self) -> Result<Vec<u8>, CryptoError> {
        signed_payload(
            &self.context.engine.signing[0].1,
            &sha256(&self.protected),
            &self.context.document,
        )
        .map(|payload| payload.to_vec())
    }

    /// Re-seals with the fixture content key and HPKE seeds, from the given parts.
    fn rebuild(&self, parts: &Rebuild<'_>) -> Result<Vec<u8>, CryptoError> {
        let protected_hash = sha256(parts.protected);
        let content_key = <[u8; 32]>::try_from(&self.context.random[0..32])
            .map_err(|_| CryptoError::Permanent)?;
        let content_nonce = <[u8; 12]>::try_from(&self.context.random[32..44])
            .map_err(|_| CryptoError::Permanent)?;
        let ciphertext = match parts.ciphertext {
            Some(ciphertext) => ciphertext.to_vec(),
            None => encrypt_content(
                parts.payload,
                &content_key,
                content_nonce,
                parts
                    .content_aad
                    .as_deref()
                    .unwrap_or(&content_aad(&protected_hash)),
            )?,
        };
        let recipients = sorted_recipients(self.context.request().recipients);
        let mut wrappers = Vec::with_capacity(2);
        for (index, binding) in recipients.iter().enumerate() {
            let offset = 44 + index * 32;
            let seed = <[u8; 32]>::try_from(
                self.context
                    .random
                    .get(offset..offset + 32)
                    .ok_or(CryptoError::Permanent)?,
            )
            .map_err(|_| CryptoError::Permanent)?;
            let mut aad = hpke_aad(&protected_hash, &recipient_descriptor(binding)?);
            if parts.flip_hpke_aad == Some(index) {
                *aad.last_mut().ok_or(CryptoError::Permanent)? ^= 1;
            }
            let (enc, wrapped_key) = wrap_content_key(
                &binding.public_key,
                &hpke_info(&protected_hash),
                &aad,
                &content_key,
                &seed,
            )
            .map_err(|rejection| rejection.error)?;
            wrappers.push(json!({"enc": b64(&enc), "wrapped_key": b64(&wrapped_key)}));
        }
        assemble_envelope(parts.protected, &ciphertext, wrappers)
    }

    /// Re-seals the vector with `mutate` applied to its signed payload.
    fn with_payload(&self, mutate: impl FnOnce(&mut Vec<u8>)) -> Result<Vec<u8>, CryptoError> {
        let mut payload = self.payload()?;
        mutate(&mut payload);
        self.rebuild(&Rebuild {
            protected: &self.protected,
            payload: &payload,
            ..Rebuild::default()
        })
    }
}

/// Parts for [`Fixture::rebuild`].
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
struct Rebuild<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    /// Keeps this content ciphertext instead of encrypting `payload`.
    ciphertext: Option<&'a [u8]>,
    /// Encrypts the content under this AAD instead of the one the header implies.
    content_aad: Option<Vec<u8>>,
    /// Wraps recipient `i`'s key under an HPKE AAD with one bit flipped.
    flip_hpke_aad: Option<usize>,
}

/// Flips the first or last bit of a base64url member, keeping it a well-formed encoding.
#[cfg(any(test, feature = "test-support"))]
fn flip_member(value: &mut Value, key: &str, last: bool) -> Option<()> {
    let mut bytes = URL_SAFE_NO_PAD.decode(value.get(key)?.as_str()?).ok()?;
    let byte = if last {
        bytes.last_mut()?
    } else {
        bytes.first_mut()?
    };
    *byte ^= 1;
    *value.get_mut(key)? = json!(b64(&bytes));
    Some(())
}

#[cfg(any(test, feature = "test-support"))]
fn reader_wrapper(envelope: &mut Value) -> Option<&mut Value> {
    envelope.get_mut("recipients")?.as_array_mut()?.get_mut(1)
}

/// The vector document with `insert` placed right after its opening brace.
#[cfg(any(test, feature = "test-support"))]
fn document_with(context: &VectorContext, insert: &[u8]) -> Vec<u8> {
    let mut document = b"{".to_vec();
    document.extend_from_slice(insert);
    document.extend_from_slice(context.document.get(1..).unwrap_or_default());
    document
}

/// X25519 u-coordinates of low order; any scalar gives an all-zero shared secret with them.
#[cfg(any(test, feature = "test-support"))]
const LOW_ORDER_X25519: [[u8; 32]; 3] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
];

/// The key registry's verdict on `binding` re-signed by the fixture authority with its public key
/// cut to 31 bytes, gated against the same record with the whole key, so only the length differs.
#[cfg(any(test, feature = "test-support"))]
fn short_key_record(
    binding: &VerifiedBinding,
    purpose: &str,
    algorithm: &str,
) -> Result<CaseOutcome, CryptoError> {
    let (authority, authority_public, authority_key_id) = registry_authority()?;
    let record = |public_key: &[u8]| {
        let prefix = if algorithm == "Ed25519" {
            "sig-ed25519-"
        } else {
            "kem-x25519-"
        };
        vector_binding_record(
            &authority_key_id,
            &authority,
            VectorBinding {
                sequence: binding.sequence,
                wallet: &binding.wallet,
                key_id: &format!("{prefix}{}", b64(&sha256(public_key))),
                purpose,
                algorithm,
                public_key,
                expected_digest: None,
            },
        )
    };
    let whole = record(&binding.public_key)?;
    let short = record(binding.public_key.get(..31).ok_or(CryptoError::Permanent)?)?;
    let verify = |record: &[u8]| {
        crate::providers::verify_binding_record(record, &authority_public).map(|_| ())
    };
    Ok(gate(
        RejectionStage::KeyValidation,
        verify(&whole),
        verify(&short),
    ))
}

/// Every sub-mutation of one fixture mutation ID, applied to the vector's own inputs.
#[cfg(any(test, feature = "test-support"))]
#[expect(
    clippy::too_many_lines,
    reason = "one table of every fixture sub-mutation reads best in one place"
)]
fn negative_cases(
    fixture: &Fixture,
    mutation: Mutation,
) -> Result<Vec<(&'static str, CaseOutcome)>, CryptoError> {
    let context = &fixture.context;
    let parse = |bytes: &[u8]| parse_document(bytes).map(|_| ());
    Ok(match mutation {
        Mutation::N01 => {
            let duplicated_document = document_with(context, br#""statement":"x","#);
            let duplicated_payload = signed_payload(
                &context.engine.signing[0].1,
                &sha256(&fixture.protected),
                &duplicated_document,
            )?;
            let duplicated = fixture.rebuild(&Rebuild {
                protected: &fixture.protected,
                payload: &duplicated_payload,
                ..Rebuild::default()
            })?;
            vec![
                (
                    "duplicate top-level statement member in the sent document",
                    gate(
                        RejectionStage::StrictParse,
                        parse(&context.document),
                        parse(&duplicated_document),
                    ),
                ),
                (
                    "duplicate top-level statement member in the signed payload",
                    fixture.open(&duplicated),
                ),
            ]
        }
        Mutation::N02 => vec![
            (
                "fractional number",
                gate(
                    RejectionStage::StrictProfile,
                    parse(&document_with(context, br#""extra":1,"#)),
                    parse(&document_with(context, br#""extra":1.5,"#)),
                ),
            ),
            (
                "invalid UTF-8",
                gate(
                    RejectionStage::StrictProfile,
                    parse(&document_with(context, b"\"extra\":\"a\",")),
                    parse(&document_with(context, b"\"extra\":\"\xff\",")),
                ),
            ),
            (
                "lone surrogate",
                gate(
                    RejectionStage::StrictProfile,
                    parse(&document_with(context, br#""extra":"\u00e9","#)),
                    parse(&document_with(context, br#""extra":"\ud800","#)),
                ),
            ),
        ],
        Mutation::N03 => {
            let schema_bytes =
                include_bytes!("../../../schemas/service-application/1.0.0.schema.json");
            let approved = |bytes: &[u8]| {
                parse_document(bytes)
                    .ok()
                    .filter(|schema| {
                        sha256(schema.bytes())
                            == crate::providers::APPROVED_SERVICE_APPLICATION_DIGEST
                    })
                    .ok_or(())
            };
            let substituted = String::from_utf8_lossy(schema_bytes)
                .replace("\"maxLength\": 2000", "\"maxLength\": 2001")
                .into_bytes();
            let compiled = parse_document(schema_bytes)
                .and_then(|schema| docchain_domain::CompiledSchema::compile(schema.value()))
                .map_err(|_| CryptoError::Permanent)?;
            let validate = |bytes: &[u8]| {
                parse_document(bytes).and_then(|document| compiled.validate(document.value()))
            };
            let leap_day = String::from_utf8_lossy(&context.document)
                .replace(
                    "\"submittedOn\":\"2026-09-19\"",
                    "\"submittedOn\":\"2026-02-29\"",
                )
                .into_bytes();
            let oversize = format!("\"{}\"", "a".repeat(MAX_DOCUMENT_BYTES)).into_bytes();
            let deep = format!("{}{}", "[".repeat(33), "]".repeat(33)).into_bytes();
            let shallow = format!("{}{}", "[".repeat(32), "]".repeat(32)).into_bytes();
            let mut oversize_request = context.request();
            oversize_request.canonical_document = &oversize;
            vec![
                (
                    "schema digest mismatch",
                    gate(
                        RejectionStage::BeforeEncryption,
                        approved(schema_bytes),
                        approved(&substituted),
                    ),
                ),
                (
                    "schema-invalid document",
                    gate(
                        RejectionStage::BeforeEncryption,
                        validate(&context.document),
                        validate(br#"{"applicationReference":"SYN-APP0001"}"#),
                    ),
                ),
                (
                    "impossible date 2026-02-29",
                    gate(
                        RejectionStage::BeforeEncryption,
                        validate(&context.document),
                        validate(&leap_day),
                    ),
                ),
                (
                    "document over 256 KiB",
                    gate(
                        RejectionStage::BeforeEncryption,
                        parse(b"\"a\""),
                        parse(&oversize),
                    ),
                ),
                (
                    "document over 256 KiB at the seal boundary",
                    outcome(
                        context
                            .engine
                            .seal_staged(&oversize_request, &context.random),
                    ),
                ),
                (
                    "document deeper than 32",
                    gate(
                        RejectionStage::BeforeEncryption,
                        parse(&shallow),
                        parse(&deep),
                    ),
                ),
            ]
        }
        Mutation::N04 => {
            let reader = &context.recipients[1];
            let sender = &context.sender_signing;
            let other_wallet =
                WalletId::new("wal_0000000000000003").map_err(|_| CryptoError::Permanent)?;
            let reader_with = |change: fn(&mut VerifiedBinding, &WalletId, &VerifiedBinding)| {
                let mut binding = reader.clone();
                change(&mut binding, &other_wallet, &context.recipients[0]);
                fixture.open_with(&binding, sender)
            };
            let sender_with = |change: fn(&mut VerifiedBinding, &WalletId)| {
                let mut binding = sender.clone();
                change(&mut binding, &other_wallet);
                fixture.open_with(reader, &binding)
            };
            vec![
                (
                    "reader binding for another wallet",
                    reader_with(|binding, wallet, _| binding.wallet = wallet.clone()),
                ),
                (
                    "reader binding with the signing purpose",
                    reader_with(|binding, _, _| binding.purpose = KeyPurpose::DocumentSigning),
                ),
                (
                    "reader binding for another key",
                    reader_with(|binding, _, other| binding.key_id.clone_from(&other.key_id)),
                ),
                (
                    "reader binding record changed",
                    reader_with(|binding, _, _| binding.binding_digest[0] ^= 1),
                ),
                (
                    "sender binding for another wallet",
                    sender_with(|binding, wallet| binding.wallet = wallet.clone()),
                ),
                (
                    "sender binding with the encryption purpose",
                    sender_with(|binding, _| binding.purpose = KeyPurpose::DocumentEncryption),
                ),
                (
                    "sender binding record changed",
                    sender_with(|binding, _| binding.binding_digest[0] ^= 1),
                ),
            ]
        }
        Mutation::N05 => {
            let mut cases = vec![
                (
                    "31-byte X25519 encapsulated key",
                    fixture.open(&fixture.edit(|envelope| {
                        *reader_wrapper(envelope)?.get_mut("enc")? = json!(b64(&[9_u8; 31]));
                        Some(())
                    })?),
                ),
                (
                    "all-zero encapsulated key",
                    fixture.open(&fixture.edit(|envelope| {
                        *reader_wrapper(envelope)?.get_mut("enc")? = json!(b64(&[0_u8; 32]));
                        Some(())
                    })?),
                ),
                (
                    "31-byte Ed25519 signing key in a signed binding record",
                    short_key_record(&context.sender_signing, "document-signing", "Ed25519")?,
                ),
                (
                    "31-byte X25519 encryption key in a signed binding record",
                    short_key_record(&context.recipients[1], "document-encryption", "X25519")?,
                ),
                ("low-order Ed25519 sender key", {
                    let mut sender = context.sender_signing.clone();
                    sender.public_key = LOW_ORDER_X25519[0];
                    fixture.open_with(&context.recipients[1], &sender)
                }),
            ];
            let names = [
                "all-zero recipient key",
                "low-order recipient key u = 1",
                "low-order recipient key of order 8, first",
                "low-order recipient key of order 8, second",
            ];
            for (name, public_key) in names
                .into_iter()
                .zip([[0_u8; 32]].into_iter().chain(LOW_ORDER_X25519))
            {
                let mut recipient = context.recipients[1].clone();
                recipient.public_key = public_key;
                let mut request = context.request();
                request.recipients = [&context.recipients[0], &recipient];
                cases.push((
                    name,
                    outcome(context.engine.seal_staged(&request, &context.random)),
                ));
            }
            cases
        }
        Mutation::N06 => vec![
            (
                "HPKE AEAD ID 3 changed to 2",
                fixture.open(&fixture.edit_protected(|protected| {
                    *protected.get_mut("algorithms")?.get_mut("hpke_aead_id")? = json!(2);
                    Some(())
                })?),
            ),
            (
                "envelope version 1 changed to 0",
                fixture.open(&fixture.edit_protected(|protected| {
                    *protected.get_mut("envelope_version")? = json!(0);
                    Some(())
                })?),
            ),
        ],
        Mutation::N07 => {
            let substitute = format!("kem-x25519-{}", b64(&sha256(b"substituted key")));
            vec![
                (
                    "recipient inserted",
                    fixture.open(&fixture.edit_protected(|protected| {
                        let recipients = protected.get_mut("recipients")?.as_array_mut()?;
                        let mut inserted = recipients.get(1)?.clone();
                        *inserted.get_mut("wallet_id")? = json!("wal_0000000000000003");
                        recipients.push(inserted);
                        Some(())
                    })?),
                ),
                (
                    "recipient removed",
                    fixture.open(&fixture.edit_protected(|protected| {
                        protected
                            .get_mut("recipients")?
                            .as_array_mut()?
                            .pop()
                            .map(|_| ())
                    })?),
                ),
                (
                    "recipients reordered",
                    fixture.open(&fixture.edit_protected(|protected| {
                        protected.get_mut("recipients")?.as_array_mut()?.swap(0, 1);
                        Some(())
                    })?),
                ),
                (
                    "recipient key substituted",
                    fixture.open(&fixture.edit_protected(|protected| {
                        let recipient = protected
                            .get_mut("recipients")?
                            .as_array_mut()?
                            .get_mut(1)?;
                        *recipient.get_mut("encryption_key_id")? = json!(substitute);
                        Some(())
                    })?),
                ),
                (
                    "wrapper inserted",
                    fixture.open(&fixture.edit(|envelope| {
                        let wrappers = envelope.get_mut("recipients")?.as_array_mut()?;
                        let copy = wrappers.get(1)?.clone();
                        wrappers.push(copy);
                        Some(())
                    })?),
                ),
                (
                    "wrapper removed",
                    fixture.open(&fixture.edit(|envelope| {
                        envelope
                            .get_mut("recipients")?
                            .as_array_mut()?
                            .pop()
                            .map(|_| ())
                    })?),
                ),
            ]
        }
        Mutation::N08 => {
            let original = parse_outer(&fixture.bytes)
                .map_err(|rejection| rejection.error)?
                .ciphertext;
            let renonced = fixture
                .protected_with(|protected| flip_member(protected, "content_nonce", false))?;
            let renonced_envelope = fixture.rebuild(&Rebuild {
                protected: &renonced,
                ciphertext: Some(&original),
                ..Rebuild::default()
            })?;
            // As if the changed header had been committed, so only content opening can object.
            let renonced_header =
                inspect_staged(&renonced_envelope).map_err(|rejection| rejection.error)?;
            let payload = fixture.payload()?;
            vec![
                (
                    "ciphertext bit flip",
                    fixture.open(
                        &fixture.edit(|envelope| flip_member(envelope, "ciphertext", false))?,
                    ),
                ),
                (
                    "content tag bit flip",
                    fixture
                        .open(&fixture.edit(|envelope| flip_member(envelope, "ciphertext", true))?),
                ),
                (
                    "content nonce bit flip",
                    outcome(fixture.open_as(
                        &renonced_envelope,
                        &renonced_header,
                        &context.recipients[1],
                        &context.sender_signing,
                    )),
                ),
                (
                    "content AAD bit flip",
                    fixture.open(&fixture.rebuild(&Rebuild {
                        protected: &fixture.protected,
                        payload: &payload,
                        content_aad: Some({
                            let mut aad = content_aad(&sha256(&fixture.protected));
                            if let Some(byte) = aad.last_mut() {
                                *byte ^= 1;
                            }
                            aad
                        }),
                        ..Rebuild::default()
                    })?),
                ),
            ]
        }
        Mutation::N09 => {
            let payload = fixture.payload()?;
            vec![
                (
                    "HPKE AAD bit flip",
                    fixture.open(&fixture.rebuild(&Rebuild {
                        protected: &fixture.protected,
                        payload: &payload,
                        flip_hpke_aad: Some(1),
                        ..Rebuild::default()
                    })?),
                ),
                (
                    "encapsulated key bit flip",
                    fixture.open(
                        &fixture.edit(|envelope| {
                            flip_member(reader_wrapper(envelope)?, "enc", false)
                        })?,
                    ),
                ),
                (
                    "wrapped key bit flip",
                    fixture.open(&fixture.edit(|envelope| {
                        flip_member(reader_wrapper(envelope)?, "wrapped_key", false)
                    })?),
                ),
                (
                    "wrapper tag bit flip",
                    fixture.open(&fixture.edit(|envelope| {
                        flip_member(reader_wrapper(envelope)?, "wrapped_key", true)
                    })?),
                ),
            ]
        }
        Mutation::N10 => {
            let digest_at = 8 + context.document.len();
            let signature_at = digest_at + 32;
            vec![
                (
                    "encrypted digest bit flip",
                    fixture.open(&fixture.with_payload(|payload| {
                        if let Some(byte) = payload.get_mut(digest_at) {
                            *byte ^= 1;
                        }
                    })?),
                ),
                (
                    "encrypted signature bit flip",
                    fixture.open(&fixture.with_payload(|payload| {
                        if let Some(byte) = payload.get_mut(signature_at) {
                            *byte ^= 1;
                        }
                    })?),
                ),
                (
                    "encrypted digest bit flip, re-signed by the sender key",
                    fixture.open(&fixture.with_payload(|payload| {
                        let Some(byte) = payload.get_mut(digest_at) else {
                            return;
                        };
                        *byte ^= 1;
                        // A valid signature over the changed digest leaves only the
                        // digest-to-document comparison to object.
                        let signature_input = [
                            SIGNATURE_LABEL,
                            sha256(&fixture.protected).as_slice(),
                            payload.get(digest_at..signature_at).unwrap_or_default(),
                        ]
                        .concat();
                        let signature: [u8; 64] =
                            context.engine.signing[0].1.sign(&signature_input).into();
                        payload.truncate(signature_at);
                        payload.extend_from_slice(&signature);
                    })?),
                ),
            ]
        }
        Mutation::N11 => vec![
            (
                "payload truncated by one byte",
                fixture.open(&fixture.with_payload(|payload| {
                    payload.pop();
                })?),
            ),
            (
                "payload with a trailing 0x00 byte",
                fixture.open(&fixture.with_payload(|payload| payload.push(0))?),
            ),
        ],
        // Replay is refused by the exchange store's uniqueness constraints, which the replay
        // system tests observe. What the envelope contributes is determinism: the same request
        // under the same entropy re-seals to the same bytes, so a replay can never introduce a
        // second distinct object or commitment.
        Mutation::N12 => {
            let again = context
                .engine
                .seal_staged(&context.request(), &context.random)
                .map_err(|rejection| rejection.error)?;
            vec![(
                "re-sealing the same request yields the same bytes",
                if again.bytes == fixture.bytes {
                    Err(None)
                } else {
                    Ok(())
                },
            )]
        }
        Mutation::N13 => vec![(
            "content key, nonce, and HPKE entropy unavailable",
            outcome(seal_from_entropy(&context.engine, &context.request())),
        )],
    })
}

/// Runs every sub-mutation of one fixture mutation ID against the normative vector.
///
/// # Errors
///
/// A [`CryptoError`] when the unmutated vector cannot be built or opened, or when a mutation
/// cannot be applied, so a mutation that changes nothing never reports a rejection.
#[cfg(any(test, feature = "test-support"))]
pub fn run_negative_vector(mutation: Mutation) -> Result<Vec<NegativeCase>, CryptoError> {
    let fixture = Fixture::new()?;
    Ok(negative_cases(&fixture, mutation)?
        .into_iter()
        .map(|(case, result)| NegativeCase {
            case,
            rejected: result.is_err(),
            stage: result
                .err()
                .flatten()
                .map(|rejection| rejection.stage.fixture_text()),
        })
        .collect())
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
struct FailingEntropy;

#[cfg(any(test, feature = "test-support"))]
impl Entropy for FailingEntropy {
    fn fill(&self, _destination: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::EntropyExhausted)
    }
}

#[cfg(test)]
mod tests;
