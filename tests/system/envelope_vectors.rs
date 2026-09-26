use docchain_server::crypto::{Mutation, run_design_vector, run_negative_vector};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../vectors/envelope-v1.json"))
        .expect("data-only normative fixture")
}

#[test]
fn reproduces_envelope_v1_design_exact_bytes() {
    let outcome = run_design_vector().expect("normative vector");
    assert_eq!(
        serde_json::to_value(outcome).expect("serialize reproduced vector"),
        fixture()["expected"]
    );
}

#[test]
fn rejects_n01_through_n13_without_plaintext() {
    let fixture = fixture();
    let fixture_mutations = fixture["negative_mutations"]
        .as_array()
        .expect("negative mutation array");
    let fixture_ids = fixture_mutations
        .iter()
        .map(|mutation| mutation["id"].as_str().expect("mutation id"))
        .collect::<Vec<_>>();
    assert_eq!(fixture_ids, Mutation::ALL.map(Mutation::id));

    for (mutation, expected) in Mutation::ALL.into_iter().zip(fixture_mutations) {
        let stage = expected["rejection_stage"]
            .as_str()
            .expect("fixture rejection stage");
        let cases = run_negative_vector(mutation).expect("mutations apply to the vector");
        assert!(!cases.is_empty(), "{}", mutation.id());
        for case in cases {
            assert!(
                case.rejected,
                "{}: {} was accepted",
                mutation.id(),
                case.case
            );
            if mutation == Mutation::N12 {
                // Replay is refused by the exchange store; the replay system tests observe it.
                assert_eq!(case.stage, None, "{}: {}", mutation.id(), case.case);
            } else {
                assert_eq!(case.stage, Some(stage), "{}: {}", mutation.id(), case.case);
            }
        }
    }
}
