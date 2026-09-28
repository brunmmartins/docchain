//! Permit and removal policy of the startup sweep, over recording fakes.

use std::{
    collections::BTreeSet,
    future::Future,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

use super::*;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn object(n: u8) -> ObjectId {
    ObjectId::new(format!("obj_{n:016}")).unwrap()
}

fn set(values: &[u8]) -> BTreeSet<ObjectId> {
    values.iter().copied().map(object).collect()
}

/// The calls the fakes saw, in order.
#[derive(Default)]
struct Calls(Mutex<Vec<String>>);

impl Calls {
    fn push(&self, call: &str) {
        self.0.lock().unwrap().push(call.to_owned());
    }
    fn seen(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct Documents<'a> {
    calls: &'a Calls,
    inventory: Result<Inventory, StoreError>,
    removal: Result<RemovedCounts, StoreError>,
    removed: Mutex<Vec<DebrisEntry>>,
}

impl<'a> Documents<'a> {
    fn listing(calls: &'a Calls, objects: &[u8], temporaries: &[u8], skipped: u64) -> Self {
        Self {
            calls,
            inventory: Ok(Inventory::Listed {
                objects: set(objects),
                temporaries: set(temporaries),
                skipped,
            }),
            removal: Err(StoreError::Invariant),
            removed: Mutex::new(Vec::new()),
        }
    }
}

impl DebrisInventory for Documents<'_> {
    async fn inventory(&self) -> Result<Inventory, StoreError> {
        self.calls.push("inventory");
        self.inventory.clone()
    }

    async fn remove_debris(&self, debris: &[DebrisEntry]) -> Result<RemovedCounts, StoreError> {
        self.calls.push("remove");
        self.removed.lock().unwrap().extend_from_slice(debris);
        match self.removal {
            Ok(counts) => Ok(counts),
            // Removes as asked, unless a failure was configured.
            Err(StoreError::Invariant) => Ok(RemovedCounts {
                objects: debris
                    .iter()
                    .filter(|entry| matches!(entry, DebrisEntry::Object(_)))
                    .count() as u64,
                temporaries: debris
                    .iter()
                    .filter(|entry| matches!(entry, DebrisEntry::Temporary(_)))
                    .count() as u64,
                skipped: 0,
            }),
            Err(error) => Err(error),
        }
    }
}

struct References<'a> {
    calls: &'a Calls,
    stored: Result<BTreeSet<ObjectId>, StoreError>,
    asked: Mutex<Option<BTreeSet<ObjectId>>>,
}

impl<'a> References<'a> {
    fn stored(calls: &'a Calls, stored: &[u8]) -> Self {
        Self {
            calls,
            stored: Ok(set(stored)),
            asked: Mutex::new(None),
        }
    }
}

impl ReferenceScan for References<'_> {
    async fn referenced_among(
        &self,
        candidates: &BTreeSet<ObjectId>,
    ) -> Result<BTreeSet<ObjectId>, StoreError> {
        self.calls.push("scan");
        *self.asked.lock().unwrap() = Some(candidates.clone());
        // A fake that returns every stored reference, not only candidates, so the use case must
        // intersect.
        self.stored.clone()
    }
}

#[test]
fn every_denied_permit_makes_no_port_call() {
    for skip in [
        SweepSkip::ExclusivityNotObtained,
        SweepSkip::StoreRootNotBound,
        SweepSkip::EarlierTransactionsOpen,
        SweepSkip::InventoryOverBound,
    ] {
        let calls = Calls::default();
        let documents = Documents::listing(&calls, &[1], &[2], 0);
        let references = References::stored(&calls, &[]);
        let outcome = block_on(sweep_debris(
            SweepPermit::Denied(skip),
            &documents,
            &references,
        ));
        assert_eq!(outcome, Ok(StoreSweep::Skipped(skip)));
        assert!(calls.seen().is_empty(), "{skip:?} called a port");
    }
}

#[test]
fn removes_unreferenced_objects_and_every_temporary_after_the_scan() {
    let calls = Calls::default();
    let documents = Documents::listing(&calls, &[1, 2, 3], &[2, 9], 4);
    let references = References::stored(&calls, &[2, 3, 7]);
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(
        outcome,
        Ok(StoreSweep::Completed(SweepCounts {
            removed_objects: 1,
            removed_temporaries: 2,
            kept: 2,
            skipped: 4,
        }))
    );
    assert_eq!(calls.seen(), ["inventory", "scan", "remove"]);
    assert_eq!(*references.asked.lock().unwrap(), Some(set(&[1, 2, 3])));
    // A temporary whose object is referenced is still debris: removing its name leaves the
    // hard-linked object intact.
    assert_eq!(
        *documents.removed.lock().unwrap(),
        [
            DebrisEntry::Object(object(1)),
            DebrisEntry::Temporary(object(2)),
            DebrisEntry::Temporary(object(9)),
        ]
    );
}

#[test]
fn a_scan_error_removes_nothing() {
    for error in [
        StoreError::Transient,
        StoreError::Permanent,
        StoreError::Invariant,
    ] {
        let calls = Calls::default();
        let documents = Documents::listing(&calls, &[1], &[2], 0);
        let references = References {
            calls: &calls,
            stored: Err(error),
            asked: Mutex::new(None),
        };
        let outcome = block_on(sweep_debris(
            SweepPermit::Exclusive,
            &documents,
            &references,
        ));
        assert_eq!(outcome, Err(SweepError::References));
        assert_eq!(calls.seen(), ["inventory", "scan"]);
        assert!(documents.removed.lock().unwrap().is_empty());
    }
}

#[test]
fn the_scan_runs_even_with_no_candidates() {
    let calls = Calls::default();
    let documents = Documents::listing(&calls, &[], &[], 1);
    let references = References::stored(&calls, &[5]);
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(
        outcome,
        Ok(StoreSweep::Completed(SweepCounts {
            skipped: 1,
            ..SweepCounts::default()
        }))
    );
    assert_eq!(calls.seen(), ["inventory", "scan"]);
}

#[test]
fn a_scan_error_with_only_temporaries_removes_nothing() {
    let calls = Calls::default();
    let documents = Documents::listing(&calls, &[], &[3], 0);
    let references = References {
        calls: &calls,
        stored: Err(StoreError::Transient),
        asked: Mutex::new(None),
    };
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(outcome, Err(SweepError::References));
    assert!(documents.removed.lock().unwrap().is_empty());
}

#[test]
fn an_over_bound_inventory_skips_without_a_scan() {
    let calls = Calls::default();
    let mut documents = Documents::listing(&calls, &[], &[], 0);
    documents.inventory = Ok(Inventory::OverBound);
    let references = References::stored(&calls, &[]);
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(
        outcome,
        Ok(StoreSweep::Skipped(SweepSkip::InventoryOverBound))
    );
    assert_eq!(calls.seen(), ["inventory"]);
}

#[test]
fn an_inventory_error_maps_to_inventory() {
    let calls = Calls::default();
    let mut documents = Documents::listing(&calls, &[], &[], 0);
    documents.inventory = Err(StoreError::Permanent);
    let references = References::stored(&calls, &[]);
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(outcome, Err(SweepError::Inventory));
    assert_eq!(calls.seen(), ["inventory"]);
}

#[test]
fn a_removal_error_maps_to_removal() {
    let calls = Calls::default();
    let mut documents = Documents::listing(&calls, &[1], &[], 0);
    documents.removal = Err(StoreError::Permanent);
    let references = References::stored(&calls, &[]);
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(outcome, Err(SweepError::Removal));
}

#[test]
fn entries_skipped_at_removal_add_to_the_skipped_count() {
    let calls = Calls::default();
    let mut documents = Documents::listing(&calls, &[1, 2], &[], 3);
    documents.removal = Ok(RemovedCounts {
        objects: 1,
        temporaries: 0,
        skipped: 1,
    });
    let references = References::stored(&calls, &[]);
    let outcome = block_on(sweep_debris(
        SweepPermit::Exclusive,
        &documents,
        &references,
    ));
    assert_eq!(
        outcome,
        Ok(StoreSweep::Completed(SweepCounts {
            removed_objects: 1,
            removed_temporaries: 0,
            kept: 0,
            skipped: 4,
        }))
    );
}

#[test]
fn report_lines_carry_counts_or_a_reason_only() {
    let completed = StoreSweep::Completed(SweepCounts {
        removed_objects: 1,
        removed_temporaries: 2,
        kept: 3,
        skipped: 4,
    });
    assert_eq!(
        completed.to_string(),
        "document store sweep: removed 1 objects and 2 temporary files; kept 3 referenced \
         objects; skipped 4 entries"
    );
    for (skip, reason) in [
        (
            SweepSkip::ExclusivityNotObtained,
            "exclusivity not obtained",
        ),
        (SweepSkip::StoreRootNotBound, "store root not bound"),
        (
            SweepSkip::EarlierTransactionsOpen,
            "earlier transactions still open",
        ),
        (SweepSkip::InventoryOverBound, "inventory over bound"),
    ] {
        assert_eq!(
            StoreSweep::Skipped(skip).to_string(),
            format!("document store sweep skipped: {reason}")
        );
    }
}
