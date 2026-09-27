//! The demonstration credit rule: each accepted exchange posts exactly one balanced credit
//! transaction, a debit of one from the issuance account and a credit of one to the sender.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{ExchangeId, WalletId};

/// The account every demonstration credit is debited from.
pub const ISSUANCE_ACCOUNT: &str = "issuance";

/// The eligibility key that makes an exchange's acceptance credit postable at most once.
#[must_use]
pub fn acceptance_eligibility_key(exchange: &ExchangeId) -> String {
    format!("acceptance:{exchange}")
}

/// One stored credit transaction and its entries, exactly as read.
///
/// Every field is an untrusted stored value: nothing validates it, and a malformed value is a
/// mismatch, never an error. `exchange_id` is `None` for entries whose eligibility key has no
/// transaction row. Its `Debug` output shows only the entry count.
#[derive(Clone, PartialEq, Eq)]
pub struct CreditLedgerTransaction {
    /// The stored eligibility key.
    pub eligibility_key: String,
    /// The stored exchange, or `None` when no transaction row exists for these entries.
    pub exchange_id: Option<String>,
    /// The stored entries under this transaction's eligibility key.
    pub entries: Vec<CreditLedgerEntry>,
}

impl fmt::Debug for CreditLedgerTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreditLedgerTransaction")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// One stored credit entry, exactly as read. Its `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct CreditLedgerEntry {
    /// The stored account.
    pub account: String,
    /// The stored signed amount.
    pub amount: i64,
}

impl fmt::Debug for CreditLedgerEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CreditLedgerEntry(redacted)")
    }
}

/// The first class of disagreement between the accepted exchanges and the credit ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditMismatch {
    /// A transaction or entry refers to no accepted exchange.
    Unaccepted,
    /// An accepted exchange has more than one transaction.
    Duplicate,
    /// An accepted exchange's only transaction has the wrong key or entries.
    Unbalanced,
    /// An accepted exchange has no transaction.
    Missing,
}

/// A reconciled ledger: every accepted exchange has exactly one balanced credit transaction,
/// and every credit transaction belongs to exactly one accepted exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditReconciliation {
    accepted_exchanges: usize,
    credit_transactions: usize,
}

impl CreditReconciliation {
    /// How many accepted exchanges were reconciled.
    #[must_use]
    pub const fn accepted_exchanges(&self) -> usize {
        self.accepted_exchanges
    }

    /// How many credit transactions were reconciled; always equal to the accepted exchanges.
    #[must_use]
    pub const fn credit_transactions(&self) -> usize {
        self.credit_transactions
    }
}

/// Compares the accepted exchanges, each mapped to its sender, with the stored credit ledger.
///
/// # Errors
///
/// Returns the first failing class, in this order: [`CreditMismatch::Unaccepted`],
/// [`CreditMismatch::Duplicate`], [`CreditMismatch::Unbalanced`], [`CreditMismatch::Missing`].
pub fn reconcile_credits(
    accepted: &BTreeMap<ExchangeId, WalletId>,
    ledger: &[CreditLedgerTransaction],
) -> Result<CreditReconciliation, CreditMismatch> {
    let mut by_exchange: BTreeMap<&ExchangeId, Vec<&CreditLedgerTransaction>> = BTreeMap::new();
    for transaction in ledger {
        let exchange = transaction
            .exchange_id
            .as_deref()
            .and_then(|stored| ExchangeId::new(stored).ok())
            .and_then(|parsed| accepted.get_key_value(&parsed).map(|(key, _)| key))
            .ok_or(CreditMismatch::Unaccepted)?;
        by_exchange.entry(exchange).or_default().push(transaction);
    }
    if by_exchange
        .values()
        .any(|transactions| transactions.len() > 1)
    {
        return Err(CreditMismatch::Duplicate);
    }
    for (exchange, transactions) in &by_exchange {
        let sender = accepted.get(*exchange).ok_or(CreditMismatch::Unaccepted)?;
        if !transactions
            .iter()
            .all(|transaction| is_balanced_credit(transaction, exchange, sender))
        {
            return Err(CreditMismatch::Unbalanced);
        }
    }
    if by_exchange.len() != accepted.len() {
        return Err(CreditMismatch::Missing);
    }
    Ok(CreditReconciliation {
        accepted_exchanges: accepted.len(),
        credit_transactions: ledger.len(),
    })
}

/// Whether one transaction is exactly the expected posting for this exchange and sender.
fn is_balanced_credit(
    transaction: &CreditLedgerTransaction,
    exchange: &ExchangeId,
    sender: &WalletId,
) -> bool {
    let entries = transaction
        .entries
        .iter()
        .map(|entry| (entry.account.as_str(), entry.amount))
        .collect::<BTreeSet<_>>();
    transaction.eligibility_key == acceptance_eligibility_key(exchange)
        && transaction.entries.len() == 2
        && entries == BTreeSet::from([(ISSUANCE_ACCOUNT, -1), (sender.as_str(), 1)])
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXCHANGE_A: &str = "exc_00000000000000000000000000000001";
    const EXCHANGE_B: &str = "exc_00000000000000000000000000000002";
    const SENDER: &str = "wal_0000000000000001";
    const OTHER: &str = "wal_0000000000000003";

    fn exchange(value: &str) -> ExchangeId {
        ExchangeId::new(value).expect("fixture exchange")
    }

    fn accepted(pairs: &[(&str, &str)]) -> BTreeMap<ExchangeId, WalletId> {
        pairs
            .iter()
            .map(|(id, sender)| {
                (
                    exchange(id),
                    WalletId::new(*sender).expect("fixture wallet"),
                )
            })
            .collect()
    }

    fn entry(account: &str, amount: i64) -> CreditLedgerEntry {
        CreditLedgerEntry {
            account: account.to_owned(),
            amount,
        }
    }

    /// The posting an acceptance of `id` by a recipient of `sender` makes.
    fn posting(id: &str, sender: &str) -> CreditLedgerTransaction {
        CreditLedgerTransaction {
            eligibility_key: acceptance_eligibility_key(&exchange(id)),
            exchange_id: Some(id.to_owned()),
            entries: vec![entry(ISSUANCE_ACCOUNT, -1), entry(sender, 1)],
        }
    }

    #[test]
    fn eligibility_key_names_the_exchange() {
        assert_eq!(
            acceptance_eligibility_key(&exchange(EXCHANGE_A)),
            format!("acceptance:{EXCHANGE_A}")
        );
    }

    #[test]
    fn matching_ledger_reconciles_with_equal_counts() {
        let reconciled = reconcile_credits(
            &accepted(&[(EXCHANGE_A, SENDER), (EXCHANGE_B, OTHER)]),
            &[posting(EXCHANGE_B, OTHER), posting(EXCHANGE_A, SENDER)],
        )
        .expect("reconciled");
        assert_eq!(
            (
                reconciled.accepted_exchanges(),
                reconciled.credit_transactions()
            ),
            (2, 2)
        );
        // Entry order within a transaction does not matter.
        let mut reversed = posting(EXCHANGE_A, SENDER);
        reversed.entries.reverse();
        assert!(reconcile_credits(&accepted(&[(EXCHANGE_A, SENDER)]), &[reversed]).is_ok());
    }

    #[test]
    fn empty_history_and_empty_ledger_reconcile_to_zero() {
        let reconciled = reconcile_credits(&BTreeMap::new(), &[]).expect("reconciled");
        assert_eq!(
            (
                reconciled.accepted_exchanges(),
                reconciled.credit_transactions()
            ),
            (0, 0)
        );
    }

    #[test]
    fn each_deviation_reports_its_class() {
        let one = accepted(&[(EXCHANGE_A, SENDER)]);
        let mut orphan_entries = posting(EXCHANGE_A, SENDER);
        orphan_entries.exchange_id = None;
        let mut malformed_exchange = posting(EXCHANGE_A, SENDER);
        malformed_exchange.exchange_id = Some("not an exchange".to_owned());
        let mut truncated_exchange = posting(EXCHANGE_A, SENDER);
        truncated_exchange.exchange_id = Some(EXCHANGE_A[..EXCHANGE_A.len() - 1].to_owned());
        let mut second = posting(EXCHANGE_A, SENDER);
        second.eligibility_key = "acceptance:second".to_owned();
        let with = |change: fn(&mut CreditLedgerTransaction)| {
            let mut transaction = posting(EXCHANGE_A, SENDER);
            change(&mut transaction);
            transaction
        };
        let cases: Vec<(&str, Vec<CreditLedgerTransaction>, CreditMismatch)> = vec![
            (
                "credit for an unaccepted exchange",
                vec![posting(EXCHANGE_A, SENDER), posting(EXCHANGE_B, SENDER)],
                CreditMismatch::Unaccepted,
            ),
            (
                "entries without a transaction",
                vec![posting(EXCHANGE_A, SENDER), orphan_entries],
                CreditMismatch::Unaccepted,
            ),
            (
                "malformed exchange",
                vec![malformed_exchange],
                CreditMismatch::Unaccepted,
            ),
            (
                "truncated exchange",
                vec![truncated_exchange],
                CreditMismatch::Unaccepted,
            ),
            (
                "second transaction",
                vec![posting(EXCHANGE_A, SENDER), second],
                CreditMismatch::Duplicate,
            ),
            (
                "repeated transaction",
                vec![posting(EXCHANGE_A, SENDER), posting(EXCHANGE_A, SENDER)],
                CreditMismatch::Duplicate,
            ),
            (
                "transaction without entries",
                vec![with(|transaction| transaction.entries.clear())],
                CreditMismatch::Unbalanced,
            ),
            (
                "wrong key",
                vec![with(|transaction| {
                    transaction.eligibility_key.push('0');
                })],
                CreditMismatch::Unbalanced,
            ),
            (
                "truncated key",
                vec![with(|transaction| {
                    transaction.eligibility_key.pop();
                })],
                CreditMismatch::Unbalanced,
            ),
            (
                "wrong amount",
                vec![with(|transaction| transaction.entries[1].amount = 2)],
                CreditMismatch::Unbalanced,
            ),
            (
                "wrong credited account",
                vec![with(|transaction| {
                    transaction.entries[1].account = OTHER.to_owned();
                })],
                CreditMismatch::Unbalanced,
            ),
            (
                "wrong debited account",
                vec![with(|transaction| {
                    transaction.entries[0].account = SENDER.to_owned();
                })],
                CreditMismatch::Unbalanced,
            ),
            (
                "extra entry",
                vec![with(|transaction| {
                    transaction.entries.push(entry(OTHER, 0));
                })],
                CreditMismatch::Unbalanced,
            ),
            (
                "repeated entry",
                vec![with(|transaction| {
                    transaction.entries.push(entry(SENDER, 1));
                })],
                CreditMismatch::Unbalanced,
            ),
            (
                "single entry",
                vec![with(|transaction| {
                    transaction.entries.pop();
                })],
                CreditMismatch::Unbalanced,
            ),
            ("empty ledger", vec![], CreditMismatch::Missing),
        ];
        for (case, ledger, expected) in cases {
            assert_eq!(reconcile_credits(&one, &ledger), Err(expected), "{case}");
        }
    }

    #[test]
    fn missing_credit_for_one_of_two_acceptances_is_missing() {
        assert_eq!(
            reconcile_credits(
                &accepted(&[(EXCHANGE_A, SENDER), (EXCHANGE_B, SENDER)]),
                &[posting(EXCHANGE_A, SENDER)]
            ),
            Err(CreditMismatch::Missing)
        );
    }

    #[test]
    fn classes_follow_the_fixed_precedence() {
        let two = accepted(&[(EXCHANGE_A, SENDER), (EXCHANGE_B, SENDER)]);
        let mut unbalanced = posting(EXCHANGE_A, SENDER);
        unbalanced.entries[1].amount = 2;
        let unaccepted = posting("exc_00000000000000000000000000000009", SENDER);
        // Missing B, unbalanced A, duplicated A, and an unaccepted credit: unaccepted first.
        assert_eq!(
            reconcile_credits(
                &two,
                &[
                    unbalanced.clone(),
                    unbalanced.clone(),
                    unaccepted.clone(),
                    posting(EXCHANGE_A, SENDER),
                ]
            ),
            Err(CreditMismatch::Unaccepted)
        );
        // Without it, the duplicate precedes the unbalanced and missing classes.
        assert_eq!(
            reconcile_credits(&two, &[unbalanced.clone(), posting(EXCHANGE_A, SENDER)]),
            Err(CreditMismatch::Duplicate)
        );
        // Without the duplicate, unbalanced precedes missing.
        assert_eq!(
            reconcile_credits(&two, &[unbalanced]),
            Err(CreditMismatch::Unbalanced)
        );
    }

    #[test]
    fn debug_output_reveals_no_stored_value() {
        let transaction = posting(EXCHANGE_A, SENDER);
        let printed = format!("{transaction:?} {:?}", transaction.entries[1]);
        assert_eq!(
            printed,
            "CreditLedgerTransaction { entries: 2, .. } CreditLedgerEntry(redacted)"
        );
        for secret in [EXCHANGE_A, SENDER, ISSUANCE_ACCOUNT, "acceptance:", "-1"] {
            assert!(!printed.contains(secret), "{secret}");
        }
        let reconciled = reconcile_credits(&accepted(&[(EXCHANGE_A, SENDER)]), &[transaction])
            .expect("reconciled");
        assert_eq!(
            format!("{reconciled:?}"),
            "CreditReconciliation { accepted_exchanges: 1, credit_transactions: 1 }"
        );
    }
}
