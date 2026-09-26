mod support;

use docchain_domain::{EventKind, IdempotencyKey};

#[tokio::test]
async fn awards_one_credit_after_acceptance() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    let result = harness
        .accept(
            &harness
                .actor(&harness.recipient_credential)
                .await
                .expect("verified recipient"),
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");

    assert_eq!(result.credit_awarded, 1);
    let stats = harness.stats().await.expect("state counts");
    assert_eq!(
        (stats.events, stats.credits, stats.credit_entries),
        (2, 1, 2)
    );
    let events = harness.audit_events().await.expect("audit events");
    assert_eq!(
        events.last().map(|event| event.draft.kind),
        Some(EventKind::Accepted)
    );

    // The credit is one balanced pair: the issuance debit offsets the sender's credit.
    assert_eq!(
        harness
            .execute_unchecked(
                "SELECT 1 FROM credit_entries GROUP BY eligibility_key \
                 HAVING COUNT(*) = 2 AND SUM(amount) = 0 AND MIN(amount) = -1"
            )
            .await
            .expect("ledger query"),
        1
    );
}

const UNBALANCED_INSERT: &str = "INSERT INTO credit_entries \
    SELECT eligibility_key, 'wal_0000000000000003', 1 FROM credit_transactions";
const UNBALANCED_UPDATE: &str =
    "UPDATE credit_entries SET amount = 1 WHERE account_id = 'issuance'";
const UNBALANCED_DELETE: &str = "DELETE FROM credit_entries WHERE account_id = 'issuance'";

/// The balance trigger refuses an unbalanced credit at COMMIT even for a writer that, as the
/// table owner could, switches off the append-only refusal on `credit_entries`.
#[tokio::test]
async fn unbalanced_credit_changes_are_refused_by_the_balance_trigger() {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    harness
        .accept(
            &harness
                .actor(&harness.recipient_credential)
                .await
                .expect("verified recipient"),
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");

    for statement in [UNBALANCED_INSERT, UNBALANCED_UPDATE, UNBALANCED_DELETE] {
        assert_eq!(
            harness.sqlstate_as_owner("credit_entries", statement).await,
            Err("23514".to_owned()),
            "{statement}"
        );
    }
    // With the append-only refusal in place, the change stops before the balance check.
    for statement in [UNBALANCED_UPDATE, UNBALANCED_DELETE] {
        assert_eq!(
            harness.sqlstate_of(statement, false).await,
            Err("23001".to_owned()),
            "{statement}"
        );
    }
    assert_eq!(
        harness.stats().await.expect("state counts").credit_entries,
        2
    );
}
