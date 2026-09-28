//! Startup removal of never-committed ciphertext: the in-process service and the real server
//! binary, each on its own schema and document root.
//!
//! No assertion message carries an object ID, a path, or a binding value.
#![cfg(unix)]

mod support;

use std::{
    io::Read as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use docchain_application::{StoreSweep, SweepCounts, SweepSkip};
use docchain_domain::{DocumentVersion, IdempotencyKey, ObjectId, RequestNonce, sha256};
use docchain_server::{
    Credential, DemoHarness, DocchainService, ScanFault, SendCopyCommand, ServiceError,
    StartOptions, SweepBounds,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

/// Awaits `step`, failing the test instead of hanging when it does not finish in 30 seconds.
async fn within<T>(step: impl std::future::Future<Output = T>, what: &str) -> T {
    tokio::time::timeout(Duration::from_secs(30), step)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen"))
}

/// A fresh, valid object ID that no send produces.
fn debris_id() -> ObjectId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    ObjectId::new(format!("obj_{:08x}{n:024x}", std::process::id())).expect("debris object id")
}

/// Writes a regular file with an object name, as an interrupted send would leave it.
fn plant_object(root: &Path) -> PathBuf {
    let path = root.join(debris_id().as_str());
    std::fs::write(&path, b"never-committed ciphertext").expect("planted object");
    path
}

/// Writes a regular file with a temporary name, as an interrupted write would leave it.
fn plant_temporary(root: &Path) -> PathBuf {
    let path = root.join(format!(".{}.tmp", debris_id().as_str()));
    std::fs::write(&path, b"partial ciphertext").expect("planted temporary");
    path
}

/// The `n`th distinct valid send from the sender to the recipient.
fn request(n: u8) -> SendCopyCommand {
    let mut command = support::valid_request();
    command.document_version = DocumentVersion::new(u64::from(n)).expect("document version");
    command.request_nonce = RequestNonce::new([n; 16]);
    command.idempotency_key =
        IdempotencyKey::new(format!("idem_sweep{n:011}")).expect("idempotency key");
    command
}

fn completed(
    removed_objects: u64,
    removed_temporaries: u64,
    kept: u64,
    skipped: u64,
) -> StoreSweep {
    StoreSweep::Completed(SweepCounts {
        removed_objects,
        removed_temporaries,
        kept,
        skipped,
    })
}

fn digest(path: &Path) -> [u8; 32] {
    sha256(&std::fs::read(path).expect("stored object"))
}

/// The stored object of every committed exchange, with its SHA-256.
async fn referenced(harness: &DemoHarness) -> Vec<(PathBuf, [u8; 32])> {
    let objects: Vec<String> = sqlx::query_scalar("SELECT object_id FROM exchanges ORDER BY 1")
        .fetch_all(harness.owner_pool())
        .await
        .expect("stored references");
    objects
        .into_iter()
        .map(|object| {
            let path = harness.document_root().join(object);
            let digest = digest(&path);
            (path, digest)
        })
        .collect()
}

/// Every value in the binding file, which must never reach standard error.
fn binding_values(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join(".docchain-binding"))
        .expect("binding")
        .split_whitespace()
        .filter(|word| word.bytes().all(|byte| byte.is_ascii_digit()) && word.len() > 1)
        .map(str::to_owned)
        .collect()
}

/// A running server process, killed if a test ends before it exits.
struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Server {
    /// Starts the binary with only the harness's settings; `on_ready` runs at the first ready
    /// answer.
    async fn start(harness: &DemoHarness, on_ready: impl FnOnce()) -> Self {
        let address = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
            listener.local_addr().expect("free port address")
        };
        let child = Command::new(env!("CARGO_BIN_EXE_docchain-server"))
            .env_clear()
            .envs(harness.server_environment())
            .env("DOCCHAIN_HTTP__BIND", address.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("server binary");
        let mut server = Self { child };
        let started = Instant::now();
        while ready(address).await != Some(204) {
            if let Ok(Some(status)) = server.child.try_wait() {
                panic!("server exited before ready: {status}");
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "server not ready"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        on_ready();
        server
    }

    /// Stops the process with SIGTERM and returns its standard error.
    async fn stop(mut self) -> String {
        let status = Command::new("kill")
            .args(["-s", "TERM", &self.child.id().to_string()])
            .status()
            .expect("kill utility");
        assert!(status.success(), "kill -s TERM");
        let started = Instant::now();
        while self.child.try_wait().expect("process status").is_none() {
            assert!(started.elapsed() < Duration::from_secs(15), "no exit");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr).expect("stderr");
        }
        stderr
    }
}

/// The status of `GET /health/ready`, or `None` when the server does not answer.
async fn ready(address: SocketAddr) -> Option<u16> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    stream
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    std::str::from_utf8(response.get(9..12)?).ok()?.parse().ok()
}

/// Asserts that standard error names no planted or stored object, no store path, and no
/// binding value.
fn assert_discloses_nothing(harness: &DemoHarness, stderr: &str, objects: &[&Path]) {
    let root = harness.document_root();
    assert!(
        !stderr.contains(root.to_string_lossy().as_ref()),
        "stderr names the store root"
    );
    assert!(!stderr.contains("obj_"), "stderr names an object");
    for object in objects {
        let name = object.file_name().expect("name").to_string_lossy();
        assert!(!stderr.contains(name.as_ref()), "stderr names an object");
    }
    for value in binding_values(&root) {
        assert!(
            !stderr
                .lines()
                .any(|line| line.split_whitespace().any(|word| word == value)),
            "stderr carries a binding value"
        );
    }
}

#[tokio::test]
async fn removes_unreferenced_object_before_readiness() {
    let mut harness = support::harness().await;
    let root = harness.document_root();
    let orphan = plant_object(&root);
    harness.release_service().await.expect("service released");

    let server = Server::start(&harness, || {
        assert!(!orphan.exists(), "the orphan outlived readiness");
    })
    .await;
    let stderr = server.stop().await;

    assert!(
        stderr.contains(
            "docchain-server: document store sweep: removed 1 objects and 0 temporary files; \
             kept 0 referenced objects; skipped 0 entries\n"
        ),
        "report line missing"
    );
    assert_discloses_nothing(&harness, &stderr, &[&orphan]);
}

#[tokio::test]
async fn keeps_every_referenced_object() {
    let mut harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("recipient");
    let accepted = harness
        .send_copy(&sender, request(1))
        .await
        .expect("first delivery");
    harness
        .accept(
            &recipient,
            &accepted.exchange_id,
            &IdempotencyKey::new("idem_sweepaccept00001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");
    let delivered = harness
        .send_copy(&sender, request(2))
        .await
        .expect("second delivery");
    let before = referenced(&harness).await;
    assert_eq!(before.len(), 2);
    let orphan = plant_object(&harness.document_root());

    let report = harness
        .restart(StartOptions::default())
        .await
        .expect("restart");

    assert_eq!(report, completed(1, 0, 2, 0));
    assert!(!orphan.exists(), "the orphan remains");
    for (path, sha) in &before {
        assert_eq!(&digest(path), sha, "a referenced object changed");
    }
    harness.verify_audit(None).await.expect("audit verifies");
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("recipient");
    for exchange in [&accepted.exchange_id, &delivered.exchange_id] {
        harness
            .read_document(&recipient, exchange)
            .await
            .expect("authorized read");
    }
}

/// Instance A pauses a send inside its transaction and then loses its lease as a process exit
/// would; returns the send's task, which resolves once A's gate opens.
async fn predecessor_with_open_send(
    harness: &DemoHarness,
) -> tokio::task::JoinHandle<Result<docchain_application::Delivery, ServiceError>> {
    let gate = harness.before_send_commit_gate();
    gate.arm();
    let service = harness.service();
    let sender = support::sender(harness).await;
    let send = tokio::spawn(async move { service.send_copy(&sender, request(1)).await });
    within(gate.reached(1), "the send pausing").await;
    harness.release_lease().await.expect("lease released");
    send
}

async fn recipient_reads(
    service: &DocchainService,
    harness: &DemoHarness,
    delivery: &docchain_application::Delivery,
) {
    let recipient = service
        .authenticate(Credential::new(harness.recipient_credential.clone()))
        .await
        .expect("recipient");
    service
        .read_document(&recipient, &delivery.exchange_id)
        .await
        .expect("recipient read");
}

#[tokio::test]
async fn keeps_object_committed_after_predecessor_exit() {
    let harness = support::harness().await;
    let root = harness.document_root();
    let send = predecessor_with_open_send(&harness).await;
    let orphan = plant_object(&root);

    let drain_recorded = docchain_server::PauseGate::default();
    let successor = tokio::spawn(harness.start_instance(StartOptions {
        drain_recorded: Some(drain_recorded.clone()),
        ..StartOptions::default()
    }));
    // A commits only once B's drain has recorded A's open transaction.
    within(
        drain_recorded.reached(1),
        "the drain recording A's transaction",
    )
    .await;
    harness.before_send_commit_gate().open();
    let delivery = send.await.expect("send task").expect("send commits");
    let successor = within(successor, "the successor's start")
        .await
        .expect("successor task")
        .expect("successor composes");

    assert_eq!(successor.sweep_report(), completed(1, 0, 1, 0));
    let object = root.join(delivery.object_id.as_str());
    assert_eq!(
        digest(&object),
        delivery.envelope_commitment,
        "the committed object changed"
    );
    assert!(!orphan.exists(), "the orphan remains");
    successor.ready().await.expect("successor ready");
    recipient_reads(&successor, &harness, &delivery).await;
}

#[tokio::test]
async fn skips_sweep_while_predecessor_transaction_open() {
    let harness = support::harness().await;
    let root = harness.document_root();
    let send = predecessor_with_open_send(&harness).await;
    let orphan = plant_object(&root);
    let objects_before = harness.stats().await.expect("stats").objects;

    let successor = harness
        .start_instance(StartOptions {
            bounds: SweepBounds {
                drain: Duration::from_secs(1),
                ..SweepBounds::DEFAULT
            },
            ..StartOptions::default()
        })
        .await
        .expect("successor composes");

    assert_eq!(
        successor.sweep_report(),
        StoreSweep::Skipped(SweepSkip::EarlierTransactionsOpen)
    );
    assert_eq!(
        successor.sweep_report().to_string(),
        "document store sweep skipped: earlier transactions still open"
    );
    assert!(orphan.exists(), "the orphan was deleted");
    assert_eq!(
        harness.stats().await.expect("stats").objects,
        objects_before
    );
    successor.ready().await.expect("successor ready");
    harness.before_send_commit_gate().open();
    let delivery = send.await.expect("send task").expect("send commits");
    recipient_reads(&successor, &harness, &delivery).await;
}

/// Restarts with `options` and asserts the start fails at the reference read and deletes
/// nothing.
async fn refuses_with(
    harness: &mut DemoHarness,
    options: StartOptions,
    planted: &[&Path],
    case: &str,
) {
    let failed = harness.restart(options).await;
    assert!(
        matches!(
            failed,
            Err(ServiceError::Initialization("document store references"))
        ),
        "{case}: {failed:?}"
    );
    assert_eq!(
        failed.err().map(|error| error.to_string()).as_deref(),
        Some("service initialization failed: document store references"),
        "{case}"
    );
    for path in planted {
        assert!(path.exists(), "{case}: a planted entry was deleted");
    }
}

#[tokio::test]
async fn deletes_nothing_when_references_unknown() {
    let mut harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivery = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    let root = harness.document_root();
    let orphan = plant_object(&root);
    let temporary = plant_temporary(&root);
    let planted = [orphan.as_path(), temporary.as_path()];
    let short = SweepBounds {
        scan_statement: Duration::from_millis(500),
        scan: Duration::from_secs(2),
        ..SweepBounds::DEFAULT
    };

    for fault in [
        ScanFault::Unreachable,
        ScanFault::QueryError,
        ScanFault::Timeout,
        ScanFault::PartialStream,
    ] {
        let options = StartOptions {
            bounds: short,
            scan_fault: Some(fault),
            ..StartOptions::default()
        };
        refuses_with(&mut harness, options, &planted, &format!("{fault:?}")).await;
    }

    // An unparsable stored reference, written as the table owner could.
    let stored = delivery.object_id.as_str().to_owned();
    harness
        .tamper_as_owner("UPDATE audit_events SET object_id = 'not-an-object-id'")
        .await
        .expect("owner update");
    refuses_with(
        &mut harness,
        StartOptions::default(),
        &planted,
        "unparsable",
    )
    .await;
    harness
        .tamper_as_owner(&format!(
            "UPDATE audit_events SET object_id = '{stored}' WHERE object_id IS NOT NULL"
        ))
        .await
        .expect("owner restore");

    // A column the reference read does not cover.
    harness
        .execute_unchecked("CREATE TABLE sweep_uncovered (object_id TEXT)")
        .await
        .expect("owner create table");
    refuses_with(&mut harness, StartOptions::default(), &planted, "uncovered").await;
    harness
        .execute_unchecked("DROP TABLE sweep_uncovered")
        .await
        .expect("owner drop table");

    // With the references known again, the same start removes both.
    let report = harness
        .restart(StartOptions::default())
        .await
        .expect("restart");
    assert_eq!(report, completed(1, 1, 1, 0));
    assert!(!orphan.exists() && !temporary.exists(), "debris remains");
}

#[tokio::test]
async fn skips_sweep_without_exclusivity() {
    let harness = support::harness().await;
    let root = harness.document_root();
    let gate = harness.after_put_new_gate();
    gate.arm();
    let service = harness.service();
    let sender = support::sender(&harness).await;
    let send = tokio::spawn(async move { service.send_copy(&sender, request(1)).await });
    // The first instance has written its object and not yet committed it.
    within(gate.reached(1), "the send pausing").await;
    let orphan = plant_object(&root);
    let objects_before = harness.stats().await.expect("stats").objects;
    assert_eq!(objects_before, 2);

    let second = Server::start(&harness, || {}).await;
    assert_eq!(
        harness.stats().await.expect("stats").objects,
        objects_before
    );
    assert!(orphan.exists(), "the orphan was deleted");

    gate.open();
    let delivery = send.await.expect("send task").expect("send commits");
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("recipient");
    harness
        .read_document(&recipient, &delivery.exchange_id)
        .await
        .expect("the in-flight send reads back");
    let stderr = second.stop().await;
    assert!(
        stderr
            .contains("docchain-server: document store sweep skipped: exclusivity not obtained\n"),
        "skip line missing"
    );
    assert_discloses_nothing(&harness, &stderr, &[&orphan]);
}

#[tokio::test]
async fn ignores_foreign_entries() {
    use std::os::unix::ffi::OsStrExt as _;

    let mut harness = support::harness().await;
    let root = harness.document_root();
    let (_, fixture) = harness.fixture_location();
    let outside = fixture.join("outside-file");
    std::fs::write(&outside, b"outside the store root").expect("outside file");

    let foreign = root.join("notes.txt");
    std::fs::write(&foreign, b"foreign").expect("foreign name");
    let upper = root.join("obj_ABCDEF0123456789ABCD");
    std::fs::write(&upper, b"upper case").expect("upper-case name");
    let non_utf8 = root.join(std::ffi::OsStr::from_bytes(b"obj_\xff\xfe0000000000000000"));
    std::fs::write(&non_utf8, b"not utf-8").expect("non-UTF-8 name");
    let link = root.join(debris_id().as_str());
    std::os::unix::fs::symlink(&outside, &link).expect("symlink to an outside file");
    let dangling = root.join(debris_id().as_str());
    std::os::unix::fs::symlink(fixture.join("absent"), &dangling).expect("dangling symlink");
    let directory = root.join(debris_id().as_str());
    std::fs::create_dir(&directory).expect("directory with an object name");
    let temporary_directory = root.join(format!(".{}.tmp", debris_id().as_str()));
    std::fs::create_dir(&temporary_directory).expect("directory with a temporary name");
    // A special file with an object name. A socket stands in for a FIFO, which this
    // container's kernel policy refuses to create.
    let special = root.join(debris_id().as_str());
    let _socket = std::os::unix::net::UnixListener::bind(&special).expect("socket file");
    let orphan = plant_object(&root);

    let report = harness
        .restart(StartOptions::default())
        .await
        .expect("restart");

    assert_eq!(report, completed(1, 0, 0, 8));
    assert!(!orphan.exists(), "the orphan remains");
    assert_eq!(
        std::fs::read(&outside).expect("outside file"),
        b"outside the store root"
    );
    for entry in [
        &foreign,
        &upper,
        &non_utf8,
        &link,
        &dangling,
        &directory,
        &temporary_directory,
        &special,
    ] {
        assert!(
            std::fs::symlink_metadata(entry).is_ok(),
            "a foreign entry was removed"
        );
    }
}

#[tokio::test]
async fn recovers_from_cancelled_send() {
    let mut harness = support::harness().await;
    let root = harness.document_root();
    let temporary = plant_temporary(&root);
    let gate = harness.after_put_new_gate();
    gate.arm();
    let service = harness.service();
    let sender = support::sender(&harness).await;
    let send = tokio::spawn(async move { service.send_copy(&sender, request(1)).await });
    within(gate.reached(1), "the send pausing").await;
    // The deadline cancels the send between its write and its commit.
    send.abort();
    assert!(send.await.expect_err("cancelled").is_cancelled());
    gate.open();
    let stats = harness.stats().await.expect("stats");
    assert_eq!((stats.delivered, stats.objects), (0, 1));

    let report = harness
        .restart(StartOptions::default())
        .await
        .expect("restart");

    assert_eq!(report, completed(1, 1, 0, 0));
    assert!(!temporary.exists(), "the temporary remains");
    let sender = support::sender(&harness).await;
    let first = harness
        .send_copy(&sender, request(1))
        .await
        .expect("retry succeeds");
    let replayed = harness
        .send_copy(&sender, request(1))
        .await
        .expect("retry replays");
    assert_eq!(replayed.exchange_id, first.exchange_id);
    assert_eq!(replayed.object_id, first.object_id);
    let stats = harness.stats().await.expect("stats");
    assert_eq!((stats.delivered, stats.objects), (1, 1));
}

/// The names in the store root.
fn listing(root: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .expect("store root")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn refuses_root_bound_to_another_schema() {
    let mut harness = support::harness().await;
    let other = support::harness().await;
    let root = harness.document_root();
    harness.release_service().await.expect("service released");
    let binding = root.join(".docchain-binding");
    std::fs::remove_file(&binding).expect("own binding removed");
    std::fs::copy(other.document_root().join(".docchain-binding"), &binding)
        .expect("another schema's binding");
    let orphan = plant_object(&root);
    let before = listing(&root);

    let failed = harness.restart(StartOptions::default()).await;

    assert!(
        matches!(
            failed,
            Err(ServiceError::Initialization("document store binding"))
        ),
        "{failed:?}"
    );
    assert!(orphan.exists(), "the orphan was deleted");
    assert_eq!(listing(&root), before, "the refused root was written");
}

#[tokio::test]
async fn never_sweeps_unbound_root_with_objects() {
    let mut harness = support::harness().await;
    let root = harness.document_root();
    harness.release_service().await.expect("service released");
    std::fs::remove_file(root.join(".docchain-binding")).expect("binding removed");
    let orphan = plant_object(&root);

    let report = harness
        .restart(StartOptions::default())
        .await
        .expect("restart");

    assert_eq!(report, StoreSweep::Skipped(SweepSkip::StoreRootNotBound));
    assert!(orphan.exists(), "the orphan was deleted");
    assert!(
        !root.join(".docchain-binding").exists(),
        "an unbound root with objects was bound"
    );
}
