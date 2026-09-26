//! Independent audit: the real server binary serves the audit key and signed-event export, and
//! a verifier that holds only captured response bytes, its own challenge, a separately
//! provisioned fingerprint, and optionally a retained checkpoint checks them offline. The
//! verifier never calls the server's own verification operation.
#![cfg(unix)]

mod support;

use std::{
    io::Read as _,
    net::SocketAddr,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use docchain_domain::{DocumentVersion, IdempotencyKey, RequestNonce};
use docchain_server::DemoHarness;
use ed25519_consensus::{Signature, SigningKey, VerificationKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

// ---------------------------------------------------------------------------------------------
// The real server process and a raw HTTP/1.1 client.
// ---------------------------------------------------------------------------------------------

/// A running server binary, killed when the test ends.
struct Server {
    child: Child,
    address: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn free_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    listener.local_addr().expect("free port address")
}

fn spawn(harness: &DemoHarness, overrides: &[(&str, &str)], address: SocketAddr) -> Child {
    let mut environment = harness.server_environment();
    environment.retain(|(key, _)| !overrides.iter().any(|(name, _)| key == name));
    Command::new(env!("CARGO_BIN_EXE_docchain-server"))
        .env_clear()
        .envs(environment)
        .envs(overrides.iter().copied())
        .env("DOCCHAIN_HTTP__BIND", address.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server binary")
}

impl Server {
    /// Starts the binary with the harness's settings, changed by `overrides`, and waits until
    /// it is ready.
    async fn start(harness: &DemoHarness, overrides: &[(&str, &str)]) -> Self {
        let address = free_address();
        let mut server = Self {
            child: spawn(harness, overrides, address),
            address,
        };
        let started = Instant::now();
        while request(address, "GET", "/health/ready", None, None)
            .await
            .map(|reply| reply.status)
            != Some(204)
        {
            if let Ok(Some(status)) = server.child.try_wait() {
                panic!("server exited before ready: {status}");
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "server not ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        server
    }

    async fn send(
        &self,
        method: &str,
        target: &str,
        credential: &str,
        body: Option<&str>,
    ) -> Reply {
        request(self.address, method, target, Some(credential), body)
            .await
            .expect("HTTP response")
    }
}

/// Starts the binary with `overrides` and returns its exit status and standard error, failing
/// if it ever becomes ready.
async fn refused_start(harness: &DemoHarness, overrides: &[(&str, &str)]) -> (ExitStatus, String) {
    let address = free_address();
    let mut child = spawn(harness, overrides, address);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("process status") {
            break status;
        }
        assert!(
            request(address, "GET", "/health/ready", None, None)
                .await
                .is_none(),
            "server bound its listener"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "server kept running"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr).expect("stderr");
    }
    (status, stderr)
}

struct Reply {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

impl Reply {
    fn no_store(&self) -> bool {
        self.headers
            .to_ascii_lowercase()
            .lines()
            .any(|line| line.trim() == "cache-control: no-store")
    }

    fn category(&self) -> String {
        let value: Value = serde_json::from_slice(&self.body).expect("problem JSON");
        assert_eq!(object_keys(&value), ["category"], "problem shape");
        value["category"].as_str().expect("category").to_owned()
    }
}

/// Sends one request with every proof value in the body, never the target, and reads the whole
/// response.
async fn request(
    address: SocketAddr,
    method: &str,
    target: &str,
    credential: Option<&str>,
    body: Option<&str>,
) -> Option<Reply> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    let mut head =
        format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(credential) = credential {
        head.push_str(&format!("Authorization: Bearer {credential}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    head.push_str(body.unwrap_or_default());
    stream.write_all(head.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .ok()?
        .ok()?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let headers = String::from_utf8(response[..split].to_vec()).ok()?;
    let status = headers.get(9..12)?.parse().ok()?;
    let mut body = response[split + 4..].to_vec();
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = dechunk(&body)?;
    }
    Some(Reply {
        status,
        headers,
        body,
    })
}

fn dechunk(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line = input.windows(2).position(|window| window == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&input[..line]).ok()?, 16).ok()?;
        input = input.get(line + 2..)?;
        if size == 0 {
            return Some(output);
        }
        output.extend_from_slice(input.get(..size)?);
        input = input.get(size + 2..)?;
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture data and captured evidence.
// ---------------------------------------------------------------------------------------------

const EXPORT: &str = "/v1/audit/events/export";

/// Delivers and accepts one invented copy in-process, leaving two events.
async fn exchanged() -> DemoHarness {
    let harness = support::harness().await;
    let sender = support::sender(&harness).await;
    let delivered = harness
        .send_copy(&sender, support::valid_request())
        .await
        .expect("delivery");
    let recipient = harness
        .actor(&harness.recipient_credential)
        .await
        .expect("recipient");
    harness
        .accept(
            &recipient,
            &delivered.exchange_id,
            &IdempotencyKey::new("idem_accept0000000001").expect("acceptance key"),
        )
        .await
        .expect("acceptance");
    harness
}

/// Appends one more delivery event.
async fn append(harness: &DemoHarness, index: u8) {
    let mut command = support::valid_request();
    command.idempotency_key =
        IdempotencyKey::new(format!("idem_00000000000009{index:02}")).expect("key");
    command.request_nonce = RequestNonce::new([index; 16]);
    command.document_version = DocumentVersion::new(u64::from(index) + 1).expect("version");
    let sender = support::sender(harness).await;
    harness.send_copy(&sender, command).await.expect("append");
}

/// The auditor's fresh challenge, generated and retained outside the service.
fn challenge(seed: u8) -> [u8; 32] {
    Sha256::digest([b"invented-auditor-challenge".as_slice(), &[seed]].concat()).into()
}

fn start_body(challenge: &[u8; 32], limit: Option<u32>) -> String {
    let mut body = json!({"challenge": URL_SAFE_NO_PAD.encode(challenge)});
    if let Some(limit) = limit {
        body["limit"] = json!(limit);
    }
    body.to_string()
}

fn continuation_body(page: &Value, after_sequence: &Value, limit: u32) -> String {
    json!({
        "manifest": page["manifest"],
        "manifest_signature": page["manifest_signature"],
        "after_sequence": after_sequence,
        "limit": limit,
    })
    .to_string()
}

/// The captured bytes of every page of one export, following the service's continuation
/// markers. The verifier never trusts these markers; it checks them.
async fn export_pages(
    server: &Server,
    credential: &str,
    challenge: &[u8; 32],
    limit: u32,
) -> Vec<Vec<u8>> {
    let first = server
        .send(
            "POST",
            EXPORT,
            credential,
            Some(&start_body(challenge, Some(limit))),
        )
        .await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert!(first.no_store());
    let mut pages = vec![first.body];
    loop {
        let page: Value = serde_json::from_slice(pages.last().expect("page")).expect("JSON");
        if page["next_after_sequence"].is_null() {
            return pages;
        }
        let next = server
            .send(
                "POST",
                EXPORT,
                credential,
                Some(&continuation_body(
                    &page,
                    &page["next_after_sequence"],
                    limit,
                )),
            )
            .await;
        assert_eq!(next.status, 200, "{}", String::from_utf8_lossy(&next.body));
        assert!(next.no_store());
        pages.push(next.body);
    }
}

async fn published_key(server: &Server, credential: &str) -> Vec<u8> {
    let reply = server.send("GET", "/v1/audit/key", credential, None).await;
    assert_eq!(reply.status, 200);
    assert!(reply.no_store());
    reply.body
}

fn object_keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

fn edit(page: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(page).expect("JSON");
    change(&mut value);
    serde_json::to_vec(&value).expect("JSON")
}

fn flip_b64(value: &mut Value, index: usize) {
    let mut bytes = URL_SAFE_NO_PAD
        .decode(value.as_str().expect("base64 string"))
        .expect("base64");
    bytes[index] ^= 1;
    *value = Value::from(URL_SAFE_NO_PAD.encode(bytes));
}

// ---------------------------------------------------------------------------------------------
// The independent verifier. It uses only the published grammars, SHA-256, and Ed25519.
// ---------------------------------------------------------------------------------------------

/// The fingerprint the product owner provisioned to the auditor outside the service.
#[derive(Clone, Copy)]
struct TrustAnchor([u8; 32]);

/// A signed checkpoint the auditor retained from an earlier complete, verified export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Retained {
    sequence: u64,
    event_hash: [u8; 32],
    signature: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The pages cover the signed snapshot exactly. Without a retained checkpoint this is only
    /// a baseline; it cannot show that the service did not select an older valid prefix.
    Baseline { head: Option<Retained> },
    /// The complete snapshot still holds the retained checkpoint at its exact sequence.
    ContinuesFrom { head: Option<Retained> },
    /// The pages are a verified prefix. No snapshot head is reported.
    Partial { verified_through: u64 },
}

type Verdict<T> = Result<T, &'static str>;

fn b64<const N: usize>(value: &Value) -> Verdict<[u8; N]> {
    let text = value.as_str().ok_or("not a string")?;
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| "not base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err("noncanonical base64url");
    }
    bytes.try_into().map_err(|_| "wrong length")
}

fn closed<'a>(value: &'a Value, keys: &[&str]) -> Verdict<&'a Value> {
    let mut expected = keys.to_vec();
    expected.sort_unstable();
    if object_keys(value) != expected {
        return Err("unexpected fields");
    }
    Ok(value)
}

fn integer(value: &Value) -> Verdict<u64> {
    value.as_u64().ok_or("not an integer")
}

/// Checks the key response against the separately provisioned fingerprint. The fingerprint in
/// the response is compared, never adopted.
fn verify_key(anchor: Option<TrustAnchor>, key_response: &[u8]) -> Verdict<VerificationKey> {
    let TrustAnchor(expected) = anchor.ok_or("no independently provisioned fingerprint")?;
    let value: Value = serde_json::from_slice(key_response).map_err(|_| "key JSON")?;
    let value = closed(&value, &["public_key", "fingerprint"])?;
    let public_key: [u8; 32] = b64(&value["public_key"])?;
    let fingerprint: [u8; 32] = b64(&value["fingerprint"])?;
    let derived: [u8; 32] = Sha256::digest(public_key).into();
    if derived != expected || fingerprint != expected {
        return Err("key does not match the provisioned fingerprint");
    }
    VerificationKey::try_from(public_key).map_err(|_| "invalid public key")
}

fn head_of(value: &Value) -> Verdict<Option<Retained>> {
    if value.is_null() {
        return Ok(None);
    }
    let value = closed(value, &["sequence", "event_hash", "signature"])?;
    Ok(Some(Retained {
        sequence: integer(&value["sequence"])?,
        event_hash: b64(&value["event_hash"])?,
        signature: b64(&value["signature"])?,
    }))
}

/// The version 1 manifest signature input, from its published grammar.
fn manifest_input(
    challenge: &[u8; 32],
    fingerprint: &[u8; 32],
    count: u64,
    head: Option<Retained>,
) -> Vec<u8> {
    let mut input = b"docchain/audit-export-manifest/v1\0".to_vec();
    input.extend_from_slice(challenge);
    input.extend_from_slice(fingerprint);
    input.extend_from_slice(&count.to_be_bytes());
    match head {
        None => input.push(0),
        Some(head) => {
            input.push(1);
            input.extend_from_slice(&head.sequence.to_be_bytes());
            input.extend_from_slice(&head.event_hash);
            input.extend_from_slice(&head.signature);
        }
    }
    input
}

/// Strictly decodes a version 1 event preimage and returns its sequence and previous hash.
fn parse_preimage(bytes: &[u8]) -> Verdict<(u64, [u8; 32])> {
    fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Verdict<&'a [u8]> {
        let end = cursor.checked_add(length).ok_or("preimage overflow")?;
        let value = bytes.get(*cursor..end).ok_or("short preimage")?;
        *cursor = end;
        Ok(value)
    }
    fn number<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Verdict<[u8; N]> {
        take(bytes, cursor, N)?
            .try_into()
            .map_err(|_| "short preimage")
    }
    fn field(bytes: &[u8], cursor: &mut usize) -> Verdict<()> {
        let length = u32::from_be_bytes(number(bytes, cursor)?);
        let value = take(
            bytes,
            cursor,
            usize::try_from(length).map_err(|_| "field length")?,
        )?;
        std::str::from_utf8(value).map_err(|_| "field is not UTF-8")?;
        Ok(())
    }
    const LABEL: &[u8] = b"docchain/event/v1\0";
    if bytes.len() > 523 {
        return Err("preimage beyond the version 1 bound");
    }
    let mut cursor = 0;
    if take(bytes, &mut cursor, LABEL.len())? != LABEL {
        return Err("preimage label");
    }
    let sequence = u64::from_be_bytes(number(bytes, &mut cursor)?);
    for _ in 0..3 {
        field(bytes, &mut cursor)?; // kind, exchange, object
    }
    take(bytes, &mut cursor, 32 + 4 + 32)?; // commitment, envelope version, protected hash
    for _ in 0..3 {
        field(bytes, &mut cursor)?; // sender, recipient, document
    }
    take(bytes, &mut cursor, 8 + 8)?; // document version, registry sequence
    if i64::from_be_bytes(number(bytes, &mut cursor)?) < 0 {
        return Err("negative commit time");
    }
    let previous = number::<32>(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err("preimage trailing bytes");
    }
    Ok((sequence, previous))
}

/// Verifies one export from captured bytes only.
fn verify_export(
    anchor: Option<TrustAnchor>,
    key_response: &[u8],
    expected_challenge: &[u8; 32],
    pages: &[Vec<u8>],
    retained: Option<Retained>,
) -> Verdict<Outcome> {
    let key = verify_key(anchor, key_response)?;
    let TrustAnchor(pin) = anchor.ok_or("no independently provisioned fingerprint")?;
    let pages = pages
        .iter()
        .map(|page| serde_json::from_slice::<Value>(page).map_err(|_| "page JSON"))
        .collect::<Verdict<Vec<_>>>()?;
    let first = pages.first().ok_or("no pages")?;

    // The manifest: the verifier's own challenge, the pinned key, and a valid signature.
    let manifest = closed(
        &first["manifest"],
        &[
            "export_version",
            "challenge",
            "audit_key_fingerprint",
            "event_count",
            "head",
        ],
    )?;
    if integer(&manifest["export_version"])? != 1 {
        return Err("unknown export version");
    }
    let challenge: [u8; 32] = b64(&manifest["challenge"])?;
    let fingerprint: [u8; 32] = b64(&manifest["audit_key_fingerprint"])?;
    let count = integer(&manifest["event_count"])?;
    let head = head_of(&manifest["head"])?;
    if challenge != *expected_challenge {
        return Err("challenge mismatch");
    }
    if fingerprint != pin {
        return Err("manifest names another key");
    }
    if head.is_none() != (count == 0) || head.is_some_and(|head| head.sequence != count) {
        return Err("malformed snapshot");
    }
    let manifest_signature: [u8; 64] = b64(&first["manifest_signature"])?;
    key.verify(
        &Signature::from(manifest_signature),
        &manifest_input(&challenge, &fingerprint, count, head),
    )
    .map_err(|_| "manifest signature")?;

    // Pages: one identical manifest, contiguous ranges, and truthful coverage markers.
    let mut expected_sequence = 1_u64;
    let mut previous = [0; 32];
    let mut last_event = None;
    let mut saw_retained = false;
    let mut complete = false;
    for page in &pages {
        let page = closed(
            page,
            &[
                "manifest",
                "manifest_signature",
                "coverage",
                "events",
                "next_after_sequence",
            ],
        )?;
        if complete {
            return Err("page after complete coverage");
        }
        if page["manifest"] != first["manifest"]
            || page["manifest_signature"] != first["manifest_signature"]
        {
            return Err("changed manifest");
        }
        for event in page["events"].as_array().ok_or("events")? {
            let event = closed(
                event,
                &[
                    "preimage_version",
                    "preimage",
                    "sequence",
                    "previous_event_hash",
                    "event_hash",
                    "signature",
                ],
            )?;
            if integer(&event["preimage_version"])? != 1 {
                return Err("unknown preimage version");
            }
            let preimage = URL_SAFE_NO_PAD
                .decode(event["preimage"].as_str().ok_or("preimage")?)
                .map_err(|_| "preimage base64url")?;
            if URL_SAFE_NO_PAD.encode(&preimage) != event["preimage"].as_str().unwrap_or_default() {
                return Err("noncanonical base64url");
            }
            let sequence = integer(&event["sequence"])?;
            let previous_event_hash: [u8; 32] = b64(&event["previous_event_hash"])?;
            let event_hash: [u8; 32] = b64(&event["event_hash"])?;
            let signature: [u8; 64] = b64(&event["signature"])?;
            let (embedded_sequence, embedded_previous) = parse_preimage(&preimage)?;
            if sequence != expected_sequence || embedded_sequence != sequence {
                return Err("missing, duplicated, or reordered event");
            }
            if sequence > count {
                return Err("event outside the snapshot");
            }
            if previous_event_hash != previous || embedded_previous != previous {
                return Err("broken link");
            }
            if <[u8; 32]>::from(Sha256::digest(&preimage)) != event_hash {
                return Err("event hash mismatch");
            }
            let mut signed = b"docchain/event-signature/v1\0".to_vec();
            signed.extend_from_slice(&event_hash);
            key.verify(&Signature::from(signature), &signed)
                .map_err(|_| "event signature")?;
            let checkpoint = Retained {
                sequence,
                event_hash,
                signature,
            };
            if retained == Some(checkpoint) {
                saw_retained = true;
            }
            previous = event_hash;
            last_event = Some(checkpoint);
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or("sequence overflow")?;
        }
        let through = expected_sequence - 1;
        match (page["coverage"].as_str(), &page["next_after_sequence"]) {
            (Some("complete"), Value::Null) => {
                if through != count || last_event != head {
                    return Err("complete coverage does not reach the signed head");
                }
                complete = true;
            }
            (Some("partial"), next) => {
                if integer(next)? != through || through >= count {
                    return Err("partial marker disagrees with the page range");
                }
            }
            _ => return Err("invalid coverage marker"),
        }
    }
    if !complete {
        return Ok(Outcome::Partial {
            verified_through: expected_sequence - 1,
        });
    }
    match retained {
        None => Ok(Outcome::Baseline { head }),
        Some(_) if saw_retained => Ok(Outcome::ContinuesFrom { head }),
        Some(_) => Err("retained checkpoint absent: rollback"),
    }
}

fn anchor(harness: &DemoHarness) -> TrustAnchor {
    TrustAnchor(harness.expected_audit_fingerprint())
}

// ---------------------------------------------------------------------------------------------
// Acceptance tests.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn publishes_pinned_audit_key() {
    let harness = exchanged().await;
    let server = Server::start(&harness, &[]).await;
    let key_response = published_key(&server, &harness.auditor_credential).await;
    let value: Value = serde_json::from_slice(&key_response).expect("key JSON");
    assert_eq!(object_keys(&value), ["fingerprint", "public_key"]);

    // Only the separately provisioned value establishes trust.
    assert!(verify_key(Some(anchor(&harness)), &key_response).is_ok());
    assert_eq!(
        verify_key(None, &key_response).err(),
        Some("no independently provisioned fingerprint")
    );
    let mut wrong = harness.expected_audit_fingerprint();
    wrong[0] ^= 1;
    assert!(verify_key(Some(TrustAnchor(wrong)), &key_response).is_err());

    // A substituted key that carries its own matching fingerprint is still refused.
    let substitute = SigningKey::from([0x5a; 32]).verification_key().to_bytes();
    let substituted = json!({
        "public_key": URL_SAFE_NO_PAD.encode(substitute),
        "fingerprint": URL_SAFE_NO_PAD.encode(Sha256::digest(substitute)),
    })
    .to_string();
    assert!(verify_key(Some(anchor(&harness)), substituted.as_bytes()).is_err());

    for (credential, status) in [
        ("", 401),
        ("unknown-credential", 401),
        (harness.sender_credential.as_str(), 403),
        (harness.operator_credential.as_str(), 403),
    ] {
        let denied = server.send("GET", "/v1/audit/key", credential, None).await;
        assert_eq!(denied.status, status);
        assert!(denied.no_store());
        denied.category();
    }
    drop(server);

    // A service whose configured pin does not match its key never binds its listener.
    let mismatched = URL_SAFE_NO_PAD.encode(wrong);
    let (status, stderr) = refused_start(
        &harness,
        &[("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT", &mismatched)],
    )
    .await;
    assert!(!status.success());
    assert!(stderr.contains("audit public key fingerprint"), "{stderr}");
    assert!(!stderr.contains(&mismatched));
    let (status, stderr) = refused_start(
        &harness,
        &[("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT", "")],
    )
    .await;
    assert!(!status.success());
    assert!(
        stderr.contains("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT"),
        "{stderr}"
    );
}

#[tokio::test]
async fn exports_events_to_auditor_only() {
    let harness = exchanged().await;
    let server = Server::start(&harness, &[]).await;
    let fresh = challenge(1);
    let pages = export_pages(&server, &harness.auditor_credential, &fresh, 1).await;
    assert_eq!(pages.len(), 2);

    for page in &pages {
        let value: Value = serde_json::from_slice(page).expect("page JSON");
        assert_eq!(
            object_keys(&value),
            [
                "coverage",
                "events",
                "manifest",
                "manifest_signature",
                "next_after_sequence"
            ]
        );
        assert_eq!(
            object_keys(&value["manifest"]),
            [
                "audit_key_fingerprint",
                "challenge",
                "event_count",
                "export_version",
                "head"
            ]
        );
        assert_eq!(value["manifest"]["event_count"], 2);
        for event in value["events"].as_array().expect("events") {
            assert_eq!(
                object_keys(event),
                [
                    "event_hash",
                    "preimage",
                    "preimage_version",
                    "previous_event_hash",
                    "sequence",
                    "signature"
                ]
            );
        }
    }

    // No plaintext, plaintext digest, envelope, credential, or private key appears.
    let document = support::valid_request().document.clone();
    let canonical = docchain_domain::parse_document(&document).expect("document");
    let events = harness.audit_events().await.expect("events");
    let envelope = harness
        .envelope(&events[0].draft.exchange_id)
        .await
        .expect("envelope");
    // Binary values are prohibited both raw, inside each decoded preimage, and in their
    // base64url form, anywhere in the JSON text; text values are prohibited as they are.
    let mut binary = vec![
        Sha256::digest(&document).to_vec(),
        Sha256::digest(canonical.bytes()).to_vec(),
        envelope[..32].to_vec(),
    ];
    let mut text = vec![b"Please provide".to_vec(), b"SYN-APP0001".to_vec()];
    for credential in [
        &harness.sender_credential,
        &harness.recipient_credential,
        &harness.auditor_credential,
        &harness.operator_credential,
    ] {
        text.push(credential.clone().into_bytes());
    }
    for (key, value) in harness.server_environment() {
        if key.ends_with("PRIVATE_KEY_FILE") || key.ends_with("PRIVATE_KEY_FILES") {
            for path in value.split(',') {
                let secret = std::fs::read_to_string(path).expect("key file");
                binary.push(
                    URL_SAFE_NO_PAD
                        .decode(secret.trim())
                        .expect("key file base64url"),
                );
            }
        }
    }
    let in_json: Vec<Vec<u8>> = text
        .iter()
        .cloned()
        .chain(
            binary
                .iter()
                .map(|value| URL_SAFE_NO_PAD.encode(value).into_bytes()),
        )
        .collect();
    let in_preimage: Vec<Vec<u8>> = text.iter().chain(&binary).cloned().collect();
    let contains = |haystack: &[u8], needle: &[u8]| {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    };
    let mut preimages = 0;
    for page in &pages {
        for needle in &in_json {
            assert!(
                !contains(page, needle),
                "{}",
                String::from_utf8_lossy(needle)
            );
        }
        let value: Value = serde_json::from_slice(page).expect("page JSON");
        for event in value["events"].as_array().expect("events") {
            let preimage = URL_SAFE_NO_PAD
                .decode(event["preimage"].as_str().expect("preimage"))
                .expect("preimage base64url");
            preimages += 1;
            for (index, needle) in in_preimage.iter().enumerate() {
                assert!(
                    !contains(&preimage, needle),
                    "prohibited value {index} inside a preimage"
                );
            }
        }
    }
    assert_eq!(preimages, events.len());

    // Only the auditor is served, and proof never travels in the request target.
    let body = start_body(&fresh, None);
    for (credential, status) in [
        ("", 401),
        (harness.sender_credential.as_str(), 403),
        (harness.recipient_credential.as_str(), 403),
        (harness.operator_credential.as_str(), 403),
    ] {
        let denied = server.send("POST", EXPORT, credential, Some(&body)).await;
        assert_eq!(denied.status, status);
        assert!(denied.no_store());
        denied.category();
    }
    let in_target = server
        .send(
            "POST",
            &format!("{EXPORT}?challenge={}", URL_SAFE_NO_PAD.encode(fresh)),
            &harness.auditor_credential,
            Some(&body),
        )
        .await;
    assert_eq!(
        (in_target.status, in_target.category()),
        (422, "invalid-request".to_owned())
    );
    assert!(in_target.no_store());
}

#[tokio::test]
async fn verifies_export_offline() {
    let harness = exchanged().await;
    let server = Server::start(&harness, &[]).await;
    let anchor = anchor(&harness);
    let key = published_key(&server, &harness.auditor_credential).await;
    let first_challenge = challenge(2);
    let pages = export_pages(&server, &harness.auditor_credential, &first_challenge, 1).await;

    // The first complete export is only a baseline for later exports.
    let Ok(Outcome::Baseline {
        head: Some(baseline),
    }) = verify_export(Some(anchor), &key, &first_challenge, &pages, None)
    else {
        panic!("baseline export");
    };
    assert_eq!(baseline.sequence, 2);

    // Alteration, insertion, removal, and reordering are each detected.
    let other_pages = export_pages(&server, &harness.auditor_credential, &challenge(3), 2).await;
    let mut tampered: Vec<(&str, Vec<Vec<u8>>)> = vec![
        (
            "preimage byte",
            vec![
                edit(&pages[0], |page| {
                    flip_b64(&mut page["events"][0]["preimage"], 40)
                }),
                pages[1].clone(),
            ],
        ),
        (
            "event hash",
            vec![
                pages[0].clone(),
                edit(&pages[1], |page| {
                    flip_b64(&mut page["events"][0]["event_hash"], 0)
                }),
            ],
        ),
        (
            "event signature",
            vec![
                edit(&pages[0], |page| {
                    flip_b64(&mut page["events"][0]["signature"], 5)
                }),
                pages[1].clone(),
            ],
        ),
        (
            "previous hash",
            vec![
                pages[0].clone(),
                edit(&pages[1], |page| {
                    flip_b64(&mut page["events"][0]["previous_event_hash"], 3);
                }),
            ],
        ),
        ("reordered pages", vec![pages[1].clone(), pages[0].clone()]),
        (
            "interior removal",
            vec![
                edit(&pages[0], |page| page["events"] = json!([])),
                pages[1].clone(),
            ],
        ),
        (
            "insertion",
            vec![
                pages[0].clone(),
                edit(&pages[1], |page| {
                    let first: Value = serde_json::from_slice(&pages[0]).expect("JSON");
                    page["events"]
                        .as_array_mut()
                        .expect("events")
                        .insert(0, first["events"][0].clone());
                }),
            ],
        ),
        (
            "reordered events",
            vec![edit(&pages[1], |page| {
                let first: Value = serde_json::from_slice(&pages[0]).expect("JSON");
                page["events"]
                    .as_array_mut()
                    .expect("events")
                    .push(first["events"][0].clone());
            })],
        ),
        (
            "manifest signature substitution",
            pages
                .iter()
                .map(|page| {
                    edit(page, |page| {
                        let other: Value = serde_json::from_slice(&other_pages[0]).expect("JSON");
                        page["manifest_signature"] = other["manifest_signature"].clone();
                    })
                })
                .collect(),
        ),
    ];
    tampered.push((
        "extra event field",
        vec![
            edit(&pages[0], |page| {
                page["events"][0]["plaintext"] = json!("x")
            }),
            pages[1].clone(),
        ],
    ));
    for (case, evidence) in &tampered {
        assert!(
            verify_export(Some(anchor), &key, &first_challenge, evidence, None).is_err(),
            "{case}"
        );
    }
    // Another export cannot answer this verifier's challenge.
    assert_eq!(
        verify_export(Some(anchor), &key, &first_challenge, &other_pages, None),
        Err("challenge mismatch")
    );

    // A later export that still holds the retained checkpoint continues from it.
    append(&harness, 1).await;
    let later_challenge = challenge(4);
    let later = export_pages(&server, &harness.auditor_credential, &later_challenge, 2).await;
    let Ok(Outcome::ContinuesFrom { head: Some(newest) }) =
        verify_export(Some(anchor), &key, &later_challenge, &later, Some(baseline))
    else {
        panic!("continuation from the retained checkpoint");
    };
    assert_eq!(newest.sequence, 3);

    // Rolling the chain back at or before the newest retained checkpoint is detected.
    harness.truncate_last_event().await.expect("truncate tail");
    let rollback_challenge = challenge(5);
    let rolled_back =
        export_pages(&server, &harness.auditor_credential, &rollback_challenge, 2).await;
    assert_eq!(
        verify_export(
            Some(anchor),
            &key,
            &rollback_challenge,
            &rolled_back,
            Some(newest)
        ),
        Err("retained checkpoint absent: rollback")
    );
    // Without that checkpoint the same shorter chain is only another baseline.
    assert!(matches!(
        verify_export(Some(anchor), &key, &rollback_challenge, &rolled_back, None),
        Ok(Outcome::Baseline { .. })
    ));
}

#[tokio::test]
async fn rejects_unpinned_key_and_partial_export() {
    // An empty chain exports one complete, headless page: a baseline and nothing more.
    let empty = support::harness().await;
    let server = Server::start(&empty, &[]).await;
    let key = published_key(&server, &empty.auditor_credential).await;
    let empty_challenge = challenge(6);
    let empty_pages = export_pages(&server, &empty.auditor_credential, &empty_challenge, 1).await;
    assert_eq!(empty_pages.len(), 1);
    assert_eq!(
        verify_export(
            Some(anchor(&empty)),
            &key,
            &empty_challenge,
            &empty_pages,
            None
        ),
        Ok(Outcome::Baseline { head: None })
    );
    drop(server);

    let harness = exchanged().await;
    let server = Server::start(&harness, &[]).await;
    let anchor = anchor(&harness);
    let key = published_key(&server, &harness.auditor_credential).await;
    let fresh = challenge(7);

    // An event appended between pages stays outside the server-selected snapshot.
    let first = server
        .send(
            "POST",
            EXPORT,
            &harness.auditor_credential,
            Some(&start_body(&fresh, Some(1))),
        )
        .await;
    assert_eq!(first.status, 200);
    append(&harness, 2).await;
    let first_value: Value = serde_json::from_slice(&first.body).expect("JSON");
    let second = server
        .send(
            "POST",
            EXPORT,
            &harness.auditor_credential,
            Some(&continuation_body(&first_value, &json!(1), 1)),
        )
        .await;
    assert_eq!(second.status, 200);
    let pages = vec![first.body.clone(), second.body.clone()];
    let Ok(Outcome::Baseline { head: Some(head) }) =
        verify_export(Some(anchor), &key, &fresh, &pages, None)
    else {
        panic!("complete snapshot export");
    };
    assert_eq!(head.sequence, 2);
    assert_eq!(harness.audit_events().await.expect("events").len(), 3);

    // Trust input: absent, response-derived for a substituted key, or mismatched.
    assert_eq!(
        verify_export(None, &key, &fresh, &pages, None),
        Err("no independently provisioned fingerprint")
    );
    let attacker = SigningKey::from([0x33; 32]);
    let attacker_public = attacker.verification_key().to_bytes();
    let attacker_fingerprint: [u8; 32] = Sha256::digest(attacker_public).into();
    let attacker_key = json!({
        "public_key": URL_SAFE_NO_PAD.encode(attacker_public),
        "fingerprint": URL_SAFE_NO_PAD.encode(attacker_fingerprint),
    })
    .to_string();
    // The attacker re-signs every event and the manifest with its own key.
    let resign = |value: &mut Value| {
        let hash: [u8; 32] = b64(&value["event_hash"]).expect("hash");
        let mut signed = b"docchain/event-signature/v1\0".to_vec();
        signed.extend_from_slice(&hash);
        value["signature"] = json!(URL_SAFE_NO_PAD.encode(attacker.sign(&signed).to_bytes()));
    };
    let attacker_pages: Vec<Vec<u8>> = pages
        .iter()
        .map(|page| {
            edit(page, |page| {
                for event in page["events"].as_array_mut().expect("events") {
                    resign(event);
                }
                resign(&mut page["manifest"]["head"]);
                page["manifest"]["audit_key_fingerprint"] =
                    json!(URL_SAFE_NO_PAD.encode(attacker_fingerprint));
                let head = head_of(&page["manifest"]["head"]).expect("head");
                let input = manifest_input(&fresh, &attacker_fingerprint, 2, head);
                page["manifest_signature"] =
                    json!(URL_SAFE_NO_PAD.encode(attacker.sign(&input).to_bytes()));
            })
        })
        .collect();
    // Trusting the fingerprint the response carries would accept the forgery, which is why
    // the verifier only takes the separately provisioned value.
    assert!(
        verify_export(
            Some(TrustAnchor(attacker_fingerprint)),
            attacker_key.as_bytes(),
            &fresh,
            &attacker_pages,
            None
        )
        .is_ok()
    );
    assert_eq!(
        verify_export(
            Some(anchor),
            attacker_key.as_bytes(),
            &fresh,
            &attacker_pages,
            None
        ),
        Err("key does not match the provisioned fingerprint")
    );
    assert_eq!(
        verify_export(Some(anchor), &key, &fresh, &attacker_pages, None),
        Err("manifest names another key")
    );
    let mut wrong = harness.expected_audit_fingerprint();
    wrong[31] ^= 1;
    assert!(verify_export(Some(TrustAnchor(wrong)), &key, &fresh, &pages, None).is_err());

    // Challenge or manifest signature mismatch.
    assert_eq!(
        verify_export(Some(anchor), &key, &challenge(8), &pages, None),
        Err("challenge mismatch")
    );
    let bad_signature: Vec<Vec<u8>> = pages
        .iter()
        .map(|page| edit(page, |page| flip_b64(&mut page["manifest_signature"], 9)))
        .collect();
    assert_eq!(
        verify_export(Some(anchor), &key, &fresh, &bad_signature, None),
        Err("manifest signature")
    );

    // Missing, duplicated, or changed pages, and a prefix presented as complete.
    assert_eq!(
        verify_export(Some(anchor), &key, &fresh, &pages[..1], None),
        Ok(Outcome::Partial {
            verified_through: 1
        })
    );
    assert!(verify_export(Some(anchor), &key, &fresh, &pages[1..], None).is_err());
    assert!(
        verify_export(
            Some(anchor),
            &key,
            &fresh,
            &[pages[0].clone(), pages[0].clone(), pages[1].clone()],
            None
        )
        .is_err()
    );
    assert!(
        verify_export(
            Some(anchor),
            &key,
            &fresh,
            &[pages[0].clone(), pages[1].clone(), pages[1].clone()],
            None
        )
        .is_err()
    );
    let changed = edit(&pages[1], |page| {
        page["manifest"]["event_count"] = json!(3);
    });
    assert_eq!(
        verify_export(
            Some(anchor),
            &key,
            &fresh,
            &[pages[0].clone(), changed],
            None
        ),
        Err("changed manifest")
    );
    let prefix_as_complete = edit(&pages[0], |page| {
        page["coverage"] = json!("complete");
        page["next_after_sequence"] = Value::Null;
    });
    assert_eq!(
        verify_export(Some(anchor), &key, &fresh, &[prefix_as_complete], None),
        Err("complete coverage does not reach the signed head")
    );

    // A retained checkpoint absent from this export is a rollback, not a new baseline.
    let mut foreign = head;
    foreign.event_hash[0] ^= 1;
    assert_eq!(
        verify_export(Some(anchor), &key, &fresh, &pages, Some(foreign)),
        Err("retained checkpoint absent: rollback")
    );

    // A client-selected historic head with a fresh challenge is not a server-selected snapshot.
    let events = harness.audit_events().await.expect("events");
    let historic = json!({
        "export_version": 1,
        "challenge": URL_SAFE_NO_PAD.encode(challenge(9)),
        "audit_key_fingerprint": first_value["manifest"]["audit_key_fingerprint"],
        "event_count": 2,
        "head": {
            "sequence": 2,
            "event_hash": URL_SAFE_NO_PAD.encode(events[1].event_hash),
            "signature": URL_SAFE_NO_PAD.encode(events[1].signature),
        },
    });
    let unanchored = server
        .send(
            "POST",
            EXPORT,
            &harness.auditor_credential,
            Some(
                &json!({
                    "manifest": historic,
                    "manifest_signature": first_value["manifest_signature"],
                    "after_sequence": 1,
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(
        (unanchored.status, unanchored.category()),
        (422, "invalid-request".to_owned())
    );
    assert!(unanchored.no_store());

    // Requests beyond a documented bound fail without a page.
    let over_body = format!(
        r#"{{"challenge":"{}"{}}}"#,
        URL_SAFE_NO_PAD.encode(fresh),
        " ".repeat(4 * 1024)
    );
    for body in [
        start_body(&fresh, Some(501)),
        start_body(&fresh, Some(0)),
        over_body,
    ] {
        let rejected = server
            .send("POST", EXPORT, &harness.auditor_credential, Some(&body))
            .await;
        assert_eq!(
            (rejected.status, rejected.category()),
            (422, "invalid-request".to_owned())
        );
        assert!(rejected.no_store());
    }
    drop(server);

    // A chain beyond the configured total returns no prefix and no head.
    let bounded = Server::start(&harness, &[("DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS", "2")]).await;
    let incomplete = bounded
        .send(
            "POST",
            EXPORT,
            &harness.auditor_credential,
            Some(&start_body(&challenge(10), Some(1))),
        )
        .await;
    assert_eq!(
        (incomplete.status, incomplete.category()),
        (503, "audit-incomplete".to_owned())
    );
    assert!(incomplete.no_store());
}
