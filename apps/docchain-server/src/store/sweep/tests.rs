//! Classifier, inventory, removal, and reference-read tests.

use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

use super::*;

const ID: &str = "obj_0123456789abcdef";

fn object(value: &str) -> ObjectId {
    ObjectId::new(value).unwrap()
}

/// A new empty directory under the temporary root, unique to the calling test.
fn scratch(line: u32) -> PathBuf {
    let root = std::env::temp_dir().join(format!("docchain_sweep_{}_{line}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn classifier_table() {
    let cases: [(&[u8], EntryName); 16] = [
        (ID.as_bytes(), EntryName::Object(object(ID))),
        (
            b".obj_0123456789abcdef.tmp",
            EntryName::Temporary(object(ID)),
        ),
        (b".docchain-lock", EntryName::Control),
        (b".docchain-binding", EntryName::Control),
        (b".docchain-binding.tmp", EntryName::Control),
        (b".docchain-binding.tmp2", EntryName::Other),
        (b"obj_0123456789ABCDEF", EntryName::Other),
        (b"obj_0123456789abcde", EntryName::Other),
        (b"obj_0123456789abcdef.tmp", EntryName::Other),
        (b".obj_0123456789abcdef", EntryName::Other),
        (b"..obj_0123456789abcdef.tmp", EntryName::Other),
        (b".ready-00ff", EntryName::Other),
        (b"notes.txt", EntryName::Other),
        (b"obj_\xff\xfe0123456789abcdef", EntryName::Other),
        (b" obj_0123456789abcdef", EntryName::Other),
        (b"", EntryName::Other),
    ];
    for (name, expected) in cases {
        assert_eq!(
            classify(OsStr::from_bytes(name)),
            expected,
            "{}",
            String::from_utf8_lossy(name)
        );
    }
}

fn store_at(root: &Path, bounds: SweepBounds) -> FileDocumentStore {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(FileDocumentStore::new(root.to_path_buf()))
        .unwrap()
        .with_bounds(bounds)
}

#[tokio::test]
async fn lists_and_removes_ten_thousand_entries_within_the_deadlines() {
    let root = scratch(line!());
    for n in 0..10_000_u32 {
        let name = if n % 2 == 0 {
            format!("obj_{n:016}")
        } else {
            format!(".obj_{n:016}.tmp")
        };
        std::fs::write(root.join(name), b"x").unwrap();
    }
    let store = FileDocumentStore::new(root.clone()).await.unwrap();
    let started = Instant::now();
    let Inventory::Listed {
        objects,
        temporaries,
        skipped,
    } = store.inventory().await.unwrap()
    else {
        panic!("over bound");
    };
    assert_eq!(
        (objects.len(), temporaries.len(), skipped),
        (5_000, 5_000, 0)
    );
    assert!(started.elapsed() < INVENTORY_DEADLINE);
    let debris: Vec<DebrisEntry> = objects
        .into_iter()
        .map(DebrisEntry::Object)
        .chain(temporaries.into_iter().map(DebrisEntry::Temporary))
        .collect();
    let started = Instant::now();
    let removed = store.remove_debris(&debris).await.unwrap();
    assert!(started.elapsed() < REMOVAL_DEADLINE);
    assert_eq!(
        removed,
        RemovedCounts {
            objects: 5_000,
            temporaries: 5_000,
            skipped: 0
        }
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn more_entries_than_the_bound_are_over_bound() {
    let root = scratch(line!());
    for n in 0..4_u32 {
        std::fs::write(root.join(format!("obj_{n:016}")), b"x").unwrap();
    }
    let bounds = SweepBounds {
        max_entries: 3,
        ..SweepBounds::DEFAULT
    };
    let store = FileDocumentStore::new(root.clone())
        .await
        .unwrap()
        .with_bounds(bounds);
    assert_eq!(store.inventory().await.unwrap(), Inventory::OverBound);
    assert_eq!(
        holds_candidate_names(&root, store.identity(), &bounds).unwrap(),
        Some(true)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn a_replaced_root_fails_listing_and_removal() {
    let root = scratch(line!());
    let store = FileDocumentStore::new(root.clone()).await.unwrap();
    let moved = root.with_extension("moved");
    std::fs::rename(&root, &moved).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join(ID), b"x").unwrap();
    assert!(store.inventory().await.is_err());
    assert!(
        store
            .remove_debris(&[DebrisEntry::Object(object(ID))])
            .await
            .is_err()
    );
    assert!(root.join(ID).exists());
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(moved).unwrap();
}

#[tokio::test]
async fn removal_leaves_entries_that_stopped_being_regular_files() {
    let root = scratch(line!());
    let outside = root.with_extension("outside");
    std::fs::write(&outside, b"outside").unwrap();
    let store = FileDocumentStore::new(root.clone()).await.unwrap();
    let linked = object("obj_1111111111111111");
    let directory = object("obj_2222222222222222");
    let gone = object("obj_3333333333333333");
    std::os::unix::fs::symlink(&outside, root.join(linked.as_str())).unwrap();
    std::fs::create_dir(root.join(format!(".{}.tmp", directory.as_str()))).unwrap();
    let removed = store
        .remove_debris(&[
            DebrisEntry::Object(linked.clone()),
            DebrisEntry::Temporary(directory.clone()),
            DebrisEntry::Object(gone),
        ])
        .await
        .unwrap();
    assert_eq!(
        removed,
        RemovedCounts {
            objects: 0,
            temporaries: 0,
            skipped: 2
        }
    );
    assert!(std::fs::symlink_metadata(root.join(linked.as_str())).is_ok());
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_file(outside).unwrap();
}

#[test]
fn store_bounds_default_to_the_named_constants() {
    let root = scratch(line!());
    let store = store_at(&root, SweepBounds::default());
    assert_eq!(store.bounds, SweepBounds::DEFAULT);
    assert_eq!(SweepBounds::DEFAULT.max_entries, 100_000);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "test-support")]
mod database {
    use sqlx::PgPool;

    use super::*;
    use crate::harness::FixtureFiles;

    async fn migrated() -> (FixtureFiles, PgPool, PgExchangeStore) {
        let fixture = FixtureFiles::write().unwrap();
        let owner = fixture.owner_pool().await.unwrap();
        fixture.create_schema(&owner).await.unwrap();
        fixture.migrate(&owner).await.unwrap();
        let store = PgExchangeStore::new(
            fixture.runtime_pool().await.unwrap(),
            fixture.schema.clone(),
        );
        (fixture, owner, store)
    }

    #[tokio::test]
    async fn an_empty_schema_reads_no_references() {
        let (_fixture, _owner, store) = migrated().await;
        let candidates: BTreeSet<ObjectId> = [object(ID)].into_iter().collect();
        assert!(
            store
                .referenced_among(&candidates)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn returns_referenced_candidates_and_fails_on_a_short_stream() {
        let harness = crate::DemoHarness::new().await.unwrap();
        let sender = harness.actor(&harness.sender_credential).await.unwrap();
        let command = crate::SendCopyCommand {
            sender: docchain_domain::WalletId::new("wal_0000000000000001").unwrap(),
            recipient: docchain_domain::WalletId::new("wal_0000000000000002").unwrap(),
            document_id: docchain_domain::DocumentId::new("doc_0000000000000001").unwrap(),
            document_version: docchain_domain::DocumentVersion::new(1).unwrap(),
            request_nonce: docchain_domain::RequestNonce::new([7; 16]),
            idempotency_key: docchain_domain::IdempotencyKey::new("idem_0000000000000001").unwrap(),
            schema_id: "urn:docchain:schema:service-application:1.0.0".to_owned(),
            schema_version: "1.0.0".to_owned(),
            document: include_bytes!("../../../../../schemas/service-application/example.json")
                .to_vec(),
        };
        let delivery = harness.send_copy(&sender, command).await.unwrap();
        let (schema, _) = harness.fixture_location();
        let store = PgExchangeStore::new(harness.runtime_pool().clone(), schema);
        let unreferenced = object(ID);
        let candidates: BTreeSet<ObjectId> = [delivery.object_id.clone(), unreferenced]
            .into_iter()
            .collect();
        let referenced = store.referenced_among(&candidates).await.unwrap();
        assert_eq!(referenced, [delivery.object_id].into_iter().collect());
        let short = store.with_scan_fault(Some(ScanFault::PartialStream));
        assert_eq!(
            short.referenced_among(&candidates).await,
            Err(StoreError::Invariant)
        );
    }

    #[tokio::test]
    async fn a_lock_taken_after_the_drain_hits_lock_timeout() {
        let (_fixture, owner, store) = migrated().await;
        let store = store.with_bounds(SweepBounds {
            scan_lock: Duration::from_millis(200),
            ..SweepBounds::DEFAULT
        });
        let mut locker = owner.begin().await.unwrap();
        sqlx::raw_sql("LOCK TABLE audit_events IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *locker)
            .await
            .unwrap();
        let started = Instant::now();
        assert!(store.referenced_among(&BTreeSet::new()).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        locker.rollback().await.unwrap();
        assert!(store.referenced_among(&BTreeSet::new()).await.is_ok());
    }
}
