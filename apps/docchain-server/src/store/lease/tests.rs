//! Lease, control-file, binding, and writer-drain tests.

use std::os::unix::fs::PermissionsExt as _;

use super::*;

const VALID: &str =
    "docchain-store-binding 1\ncluster 7340032123456789012\ndatabase 16384\nschema 2200\n";

/// A new empty directory, and an `outside` sibling path, unique to the calling test.
fn scratch(line: u32) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("docchain_lease_{}_{line}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    (root, base.join("outside"))
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

#[test]
fn binding_parsing_accepts_only_the_exact_format() {
    let parsed = BindingIdentity::parse(VALID.as_bytes()).unwrap();
    assert_eq!(
        parsed,
        BindingIdentity {
            cluster: 7_340_032_123_456_789_012,
            database: 16_384,
            schema: 2_200,
        }
    );
    assert_eq!(parsed.render(), VALID);
    let refused = [
        "",
        "docchain-store-binding 1\ncluster 1\ndatabase 2\nschema 3",
        "docchain-store-binding 2\ncluster 1\ndatabase 2\nschema 3\n",
        "docchain-store-binding 01\ncluster 1\ndatabase 2\nschema 3\n",
        "docchain-store-binding 1\ncluster 01\ndatabase 2\nschema 3\n",
        "docchain-store-binding 1\ncluster 1\ndatabase 02\nschema 3\n",
        "docchain-store-binding 1\ncluster 1\ndatabase 2\nschema 03\n",
        "docchain-store-binding 1\ncluster 1\ndatabase 2\n",
        "docchain-store-binding 1\ncluster 1\ndatabase 2\nschema 3\nextra 4\n",
        "docchain-store-binding 1\ncluster 1\ndatabase 2\nschema 3\n\n",
        "docchain-store-binding 1\r\ncluster 1\r\ndatabase 2\r\nschema 3\r\n",
        "docchain-store-binding 1\ncluster 1\ndatabase 4294967296\nschema 3\n",
        "docchain-store-binding 1\ncluster -1\ndatabase 2\nschema 3\n",
        "docchain-store-binding 1\ncluster  1\ndatabase 2\nschema 3\n",
        "docchain-store-binding 1\nschema 3\ndatabase 2\ncluster 1\n",
        "docchain-store-binding 1\ncluster 18446744073709551616\ndatabase 2\nschema 3\n",
    ];
    for text in refused {
        assert_eq!(BindingIdentity::parse(text.as_bytes()), None, "{text:?}");
    }
    assert_eq!(
        BindingIdentity::parse(
            "docchain-store-binding 1\ncluster 0\ndatabase 2\nschema 3\n".as_bytes()
        )
        .map(|identity| identity.cluster),
        Some(0)
    );
}

#[test]
fn a_binding_over_256_bytes_is_refused() {
    let (root, _) = scratch(line!());
    let mut long = VALID.to_owned();
    long.push_str(&"x".repeat(257 - long.len()));
    std::fs::write(root.join(BINDING_NAME), &long).unwrap();
    std::fs::set_permissions(
        root.join(BINDING_NAME),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(read_binding(&root).is_err());
    cleanup(&root);
}

#[test]
fn created_control_files_have_mode_0600_and_a_group_or_other_bit_is_refused() {
    let (root, _) = scratch(line!());
    let identity = BindingIdentity::parse(VALID.as_bytes()).unwrap();
    drop(open_lock_file(&root).unwrap());
    create_binding(&root, identity).unwrap();
    assert_eq!(read_binding(&root).unwrap(), Some(identity));
    for name in [LOCK_NAME, BINDING_NAME] {
        let mode = std::fs::metadata(root.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
    assert!(!root.join(BINDING_TEMPORARY_NAME).exists());
    for bits in [0o640, 0o604, 0o620] {
        for name in [LOCK_NAME, BINDING_NAME] {
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(bits))
                .unwrap();
        }
        assert!(open_lock_file(&root).is_err(), "{bits:o}");
        assert!(read_binding(&root).is_err(), "{bits:o}");
    }
    cleanup(&root);
}

#[test]
fn a_second_binding_never_replaces_the_first() {
    let (root, _) = scratch(line!());
    let first = BindingIdentity::parse(VALID.as_bytes()).unwrap();
    let second = BindingIdentity { schema: 9, ..first };
    create_binding(&root, first).unwrap();
    create_binding(&root, second).unwrap();
    assert_eq!(read_binding(&root).unwrap(), Some(first));
    cleanup(&root);
}

/// Every hostile shape of a control file: nothing outside the root is created or changed, and
/// the file is refused.
#[test]
fn control_files_are_never_followed_or_created_through_a_symlink() {
    let identity = BindingIdentity::parse(VALID.as_bytes()).unwrap();
    for name in [LOCK_NAME, BINDING_NAME, BINDING_TEMPORARY_NAME] {
        for shape in ["dangling", "outside", "directory"] {
            let (root, outside) = scratch(line!());
            let path = root.join(name);
            match shape {
                "dangling" => std::os::unix::fs::symlink(&outside, &path).unwrap(),
                "outside" => {
                    std::fs::write(&outside, VALID).unwrap();
                    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::os::unix::fs::symlink(&outside, &path).unwrap();
                }
                _ => std::fs::create_dir(&path).unwrap(),
            }
            let case = format!("{name} as {shape}");
            match name {
                LOCK_NAME => assert!(open_lock_file(&root).is_err(), "{case}"),
                BINDING_NAME => assert!(read_binding(&root).is_err(), "{case}"),
                _ => assert!(create_binding(&root, identity).is_err(), "{case}"),
            }
            match shape {
                "dangling" => assert!(!outside.exists(), "{case}: created outside the root"),
                "outside" => assert_eq!(std::fs::read_to_string(&outside).unwrap(), VALID),
                _ => assert!(path.is_dir(), "{case}"),
            }
            assert!(
                !root.join(BINDING_NAME).exists() || name == BINDING_NAME,
                "{case}"
            );
            cleanup(&root);
        }
    }
}

#[cfg(feature = "test-support")]
mod database {
    use std::time::Duration;

    use sqlx::PgPool;

    use super::*;
    use crate::{
        harness::{FixtureFiles, connect_options},
        store::PauseGate,
    };

    struct Fixture {
        files: FixtureFiles,
        owner: PgPool,
        store: FileDocumentStore,
    }

    async fn new_fixture() -> Fixture {
        let files = FixtureFiles::write().unwrap();
        let owner = files.owner_pool().await.unwrap();
        files.create_schema(&owner).await.unwrap();
        files.migrate(&owner).await.unwrap();
        let store = FileDocumentStore::new(files.object_root.clone())
            .await
            .unwrap();
        Fixture {
            files,
            owner,
            store,
        }
    }

    const SHORT: SweepBounds = SweepBounds {
        lease_wait: Duration::from_millis(500),
        drain: Duration::from_millis(500),
        ..SweepBounds::DEFAULT
    };

    async fn acquire(
        fixture: &Fixture,
        hooks: &LeaseHooks,
    ) -> Result<(StoreLease, SweepPermit), LeaseError> {
        StoreLease::acquire(
            &connect_options(&fixture.files.settings.database),
            &fixture.files.schema,
            &fixture.store,
            &SHORT,
            hooks,
        )
        .await
    }

    /// Opens a transaction as the owner holding `mode` on `exchanges`.
    async fn holding(owner: &PgPool, mode: &str) -> sqlx::Transaction<'static, sqlx::Postgres> {
        let mut transaction = owner.begin().await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "LOCK TABLE exchanges IN {mode} MODE"
        )))
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction
    }

    #[tokio::test]
    async fn a_second_lease_waits_for_the_downgrade_and_then_shares() {
        let fixture = new_fixture().await;
        let hooks = LeaseHooks::default();
        let (mut first, permit) = acquire(&fixture, &hooks).await.unwrap();
        assert_eq!(permit, SweepPermit::Exclusive);
        assert_eq!(
            acquire(&fixture, &hooks).await.err(),
            Some(LeaseError::Exclusivity)
        );
        first.downgrade(&SHORT).await.unwrap();
        let (second, permit) = acquire(&fixture, &hooks).await.unwrap();
        assert_eq!(
            permit,
            SweepPermit::Denied(SweepSkip::ExclusivityNotObtained)
        );
        second.release().await;
        first.release().await;
    }

    #[tokio::test]
    async fn the_drain_skips_while_a_write_transaction_on_the_schema_stays_open() {
        let fixture = new_fixture().await;
        let writer = holding(&fixture.owner, "ROW EXCLUSIVE").await;
        let (lease, permit) = acquire(&fixture, &LeaseHooks::default()).await.unwrap();
        assert_eq!(
            permit,
            SweepPermit::Denied(SweepSkip::EarlierTransactionsOpen)
        );
        lease.release().await;
        writer.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn the_drain_ignores_readers_and_other_schemas() {
        let fixture = new_fixture().await;
        let other = new_fixture().await;
        let reader = holding(&fixture.owner, "ACCESS SHARE").await;
        let row_share = holding(&fixture.owner, "ROW SHARE").await;
        let elsewhere = holding(&other.owner, "ROW EXCLUSIVE").await;
        let (lease, permit) = acquire(&fixture, &LeaseHooks::default()).await.unwrap();
        assert_eq!(permit, SweepPermit::Exclusive);
        lease.release().await;
        for transaction in [reader, row_share, elsewhere] {
            transaction.rollback().await.unwrap();
        }
    }

    #[tokio::test]
    async fn the_drain_ends_when_the_recorded_transaction_commits() {
        let fixture = new_fixture().await;
        let writer = holding(&fixture.owner, "ROW EXCLUSIVE").await;
        let recorded = PauseGate::default();
        let hooks = LeaseHooks {
            drain_recorded: Some(recorded.clone()),
        };
        let bounds = SweepBounds {
            drain: Duration::from_secs(10),
            ..SHORT
        };
        let options = connect_options(&fixture.files.settings.database);
        let schema = fixture.files.schema.clone();
        let root = fixture.files.object_root.clone();
        let started = tokio::spawn(async move {
            let store = FileDocumentStore::new(root).await.unwrap();
            StoreLease::acquire(&options, &schema, &store, &bounds, &hooks).await
        });
        tokio::time::timeout(Duration::from_secs(30), recorded.reached(1))
            .await
            .expect("the drain records the open transaction");
        writer.commit().await.unwrap();
        let (lease, permit) = started.await.unwrap().unwrap();
        assert_eq!(permit, SweepPermit::Exclusive);
        lease.release().await;
    }

    #[tokio::test]
    async fn a_root_bound_to_another_schema_is_refused() {
        let fixture = new_fixture().await;
        let other = new_fixture().await;
        let (lease, _) = acquire(&other, &LeaseHooks::default()).await.unwrap();
        lease.release().await;
        std::fs::copy(
            other.files.object_root.join(BINDING_NAME),
            fixture.files.object_root.join(BINDING_NAME),
        )
        .unwrap();
        assert_eq!(
            acquire(&fixture, &LeaseHooks::default()).await.err(),
            Some(LeaseError::Binding)
        );
    }
}
