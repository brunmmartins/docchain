use super::*;

fn fixture() -> Fixture {
    Fixture::new().expect("the normative vector seals and opens")
}

/// The stage of every sub-mutation of one fixture ID; `None` marks an accepted case.
fn stages(fixture: &Fixture, mutation: Mutation) -> Vec<(&'static str, Option<RejectionStage>)> {
    negative_cases(fixture, mutation)
        .expect("every sub-mutation applies")
        .into_iter()
        .map(|(case, outcome)| {
            (
                case,
                outcome.err().flatten().map(|rejection| rejection.stage),
            )
        })
        .collect()
}

fn assert_all_at(mutation: Mutation, expected: RejectionStage, count: usize) {
    let fixture = fixture();
    let observed = stages(&fixture, mutation);
    assert_eq!(observed.len(), count, "{}", mutation.id());
    for (case, stage) in observed {
        assert_eq!(stage, Some(expected), "{}: {case}", mutation.id());
    }
}

#[test]
fn n05_key_mutations_fail_at_key_validation() {
    assert_all_at(Mutation::N05, RejectionStage::KeyValidation, 9);
}

fn unsupported_aead(protected: &mut Value) -> Option<()> {
    *protected.get_mut("algorithms")?.get_mut("hpke_aead_id")? = json!(2);
    Some(())
}

fn unsupported_version(protected: &mut Value) -> Option<()> {
    *protected.get_mut("envelope_version")? = json!(0);
    Some(())
}

#[test]
fn n06_suite_and_version_mutations_fail_as_unsupported() {
    let fixture = fixture();
    for mutate in [
        unsupported_aead as fn(&mut Value) -> Option<()>,
        unsupported_version,
    ] {
        // Each field alone, and the envelope is not re-sealed around it.
        let mutated = fixture.edit_protected(mutate).expect("mutation applies");
        assert_eq!(
            fixture.context.engine.inspect(&mutated),
            Err(CryptoError::UnsupportedSuite)
        );
        assert_eq!(
            fixture.open(&mutated),
            Err(Some(
                RejectionStage::ProtectedHeader.with(CryptoError::UnsupportedSuite)
            ))
        );
    }
    assert_all_at(Mutation::N06, RejectionStage::ProtectedHeader, 2);
}

#[test]
fn n10_digest_and_signature_flips_fail_at_verification() {
    assert_all_at(Mutation::N10, RejectionStage::Verification, 3);
}

#[test]
fn n11_truncated_and_trailing_payloads_fail_at_length() {
    assert_all_at(Mutation::N11, RejectionStage::PayloadLength, 2);
}

#[test]
fn every_staged_mutation_fails_at_its_own_stage() {
    let fixture = fixture();
    for (mutation, expected) in [
        (Mutation::N01, RejectionStage::StrictParse),
        (Mutation::N02, RejectionStage::StrictProfile),
        (Mutation::N03, RejectionStage::BeforeEncryption),
        (Mutation::N04, RejectionStage::BindingValidation),
        (Mutation::N07, RejectionStage::ProtectedHashBinding),
        (Mutation::N08, RejectionStage::ContentOpening),
        (Mutation::N09, RejectionStage::RecipientWrapper),
        (Mutation::N13, RejectionStage::BeforeObjectWrite),
    ] {
        let observed = stages(&fixture, mutation);
        assert!(!observed.is_empty(), "{}", mutation.id());
        for (case, stage) in observed {
            assert_eq!(stage, Some(expected), "{}: {case}", mutation.id());
        }
    }
}

#[test]
fn seal_pairs_wrappers_with_sorted_recipients_when_the_sender_sorts_second() {
    let context = vector_context().expect("vector material");
    let third = third_wallet().expect("third wallet");
    let engine = CryptoEngine::from_material(
        vec![third.signing_seed],
        vec![
            third.encryption_ikm,
            sequential(0x60).expect("recipient input"),
        ],
        FailingEntropy,
    )
    .expect("engine");
    let recipient = context.recipients[1].clone();
    let mut request = context.request();
    request.sender_signing = &third.signing;
    // The sender's binding comes first here, but its wallet ID sorts second.
    request.recipients = [&third.encryption, &recipient];
    let sealed = engine
        .seal_staged(&request, &context.random)
        .expect("sealed envelope");

    let outer = parse_outer(&sealed.bytes).expect("well-formed envelope");
    assert_eq!(outer.header.recipients[0].wallet, recipient.wallet);
    assert_eq!(outer.header.recipients[1].wallet, third.encryption.wallet);
    for reader in [&recipient, &third.encryption] {
        let opened = engine.open_staged(
            &sealed.bytes,
            &OpenRequest {
                header: &outer.header,
                reader,
                sender_signing: &third.signing,
            },
        );
        assert_eq!(
            opened.as_deref(),
            Ok(context.document.as_slice()),
            "{}",
            reader.wallet.as_str()
        );
    }

    // Wrapper i opens with protected recipient i's key and with no other.
    let protected_hash = sha256(&outer.protected);
    for (index, (enc, wrapped_key)) in outer.wrappers.iter().enumerate() {
        let descriptor =
            recipient_descriptor_from_header(&outer.header.recipients[index]).expect("descriptor");
        let aad = hpke_aad(&protected_hash, &descriptor);
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc).expect("encapsulated key");
        for (candidate, header_key) in outer.header.recipients.iter().enumerate() {
            let material = engine
                .encryption
                .iter()
                .find(|material| material.key_id == header_key.key_id)
                .expect("private key held");
            let opens = setup_receiver::<HpkeAead, HkdfSha256, Kem>(
                &OpModeR::Base,
                &material.private,
                &enc,
                &hpke_info(&protected_hash),
            )
            .ok()
            .and_then(|mut receiver| receiver.open(wrapped_key, &aad).ok())
            .is_some();
            assert_eq!(
                opens,
                candidate == index,
                "wrapper {index}, key {candidate}"
            );
        }
    }
}

#[test]
fn fixed_rng_fails_on_an_unexpected_request() {
    let seed = [7_u8; 32];

    let mut rng = FixedRng::new(seed);
    let mut served = [0xaa_u8; 32];
    assert_eq!(rng.take(&mut served), Ok(()));
    assert_eq!(served, seed);
    assert_eq!(rng.finish(), Ok(()));
    // A second request is refused and its destination is left exactly as it was.
    let mut again = [0xaa_u8; 32];
    assert_eq!(rng.take(&mut again), Err(CryptoError::EntropyExhausted));
    assert_eq!(again, [0xaa_u8; 32]);
    assert_eq!(rng.finish(), Err(CryptoError::EntropyExhausted));

    // Through the infallible interface HPKE uses, a request of another length is recorded.
    let mut rng = FixedRng::new(seed);
    let mut short = [0xaa_u8; 16];
    assert_eq!(rng.try_fill_bytes(&mut short), Ok(()));
    assert_eq!(short, [0xaa_u8; 16]);
    assert_eq!(rng.finish(), Err(CryptoError::EntropyExhausted));
    let mut after = [0xaa_u8; 32];
    assert_eq!(rng.take(&mut after), Err(CryptoError::EntropyExhausted));
    assert_eq!(after, [0xaa_u8; 32]);
}

/// One edit to a wrapper object; `None` when it does not apply.
type WrapperChange = fn(&mut Value) -> Option<()>;

#[test]
fn open_rejects_a_malformed_unselected_wrapper() {
    let fixture = fixture();
    // The vector recipient reads wrapper 1; each change is to wrapper 0 only.
    let changes: [(&str, WrapperChange); 4] = [
        ("31-byte enc", |wrapper| {
            *wrapper.get_mut("enc")? = json!(b64(&[9_u8; 31]));
            Some(())
        }),
        ("47-byte wrapped key", |wrapper| {
            *wrapper.get_mut("wrapped_key")? = json!(b64(&[9_u8; 47]));
            Some(())
        }),
        ("non-canonical base64url enc", |wrapper| {
            let mut encoded = wrapper.get("enc")?.as_str()?.to_owned();
            let last = encoded.pop()?;
            let index = URL_SAFE_NO_PAD_ALPHABET.find(last)?;
            encoded.push(URL_SAFE_NO_PAD_ALPHABET.chars().nth(index ^ 1)?);
            *wrapper.get_mut("enc")? = json!(encoded);
            Some(())
        }),
        ("unknown wrapper member", |wrapper| {
            wrapper
                .as_object_mut()?
                .insert("extra".to_owned(), json!("x"));
            Some(())
        }),
    ];
    for (case, change) in changes {
        let mutated = fixture
            .edit(|envelope| change(envelope.get_mut("recipients")?.as_array_mut()?.get_mut(0)?))
            .expect("mutation applies");
        assert!(fixture.open(&mutated).is_err(), "{case}");
    }
}

const URL_SAFE_NO_PAD_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
