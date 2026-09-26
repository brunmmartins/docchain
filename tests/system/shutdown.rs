//! Process shutdown tests: the real server binary, on its own schema and document root.
#![cfg(unix)]

use std::{
    io::Read as _,
    net::SocketAddr,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use docchain_server::DemoHarness;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

async fn harness() -> DemoHarness {
    DemoHarness::new()
        .await
        .expect("supplied PostgreSQL and a writable temporary root")
}

/// The default ten-second drain deadline plus five seconds for the process to exit.
const EXIT_WITHIN: Duration = Duration::from_secs(15);

/// A running server process, killed if a test ends before it exits.
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

impl Server {
    /// Starts the binary with only the harness's settings, a free loopback port, and null stdin.
    async fn start(harness: &DemoHarness) -> Self {
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
        let mut server = Self { child, address };
        let started = Instant::now();
        while ready(address).await != Some(204) {
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

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args(["-s", name, &self.child.id().to_string()])
            .status()
            .expect("kill utility");
        assert!(status.success(), "kill -s {name}");
    }

    /// Waits for the process to exit and returns its status and standard error.
    async fn exit(mut self) -> (ExitStatus, String) {
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("process status") {
                break status;
            }
            assert!(started.elapsed() < EXIT_WITHIN, "server did not exit");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr).expect("stderr");
        }
        (status, stderr)
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

/// Asserts that standard error holds no credential, key, or password.
fn assert_no_secret(harness: &DemoHarness, stderr: &str) {
    let mut secrets = vec![
        harness.sender_credential.clone(),
        harness.recipient_credential.clone(),
        harness.unrelated_credential.clone(),
        harness.unkeyed_credential.clone(),
        harness.auditor_credential.clone(),
        harness.operator_credential.clone(),
    ];
    for (key, value) in harness.server_environment() {
        if key.ends_with("_FILE") || key.ends_with("_FILES") {
            for path in value.split(',') {
                if let Ok(content) = std::fs::read_to_string(path) {
                    secrets.extend(
                        content
                            .lines()
                            .map(str::trim)
                            .filter(|line| line.len() >= 8)
                            .map(str::to_owned),
                    );
                }
            }
        } else if key.ends_with("PASSWORD") {
            secrets.push(value);
        }
    }
    for secret in secrets {
        assert!(!stderr.contains(&secret), "stderr reveals a secret");
    }
}

#[tokio::test]
async fn stdin_end_of_file_does_not_stop_the_server() {
    let harness = harness().await;
    let server = Server::start(&harness).await;
    // Standard input is already at end of file; the server must keep serving.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(ready(server.address).await, Some(204));
    server.signal("TERM");
    let (status, stderr) = server.exit().await;
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_no_secret(&harness, &stderr);
}

#[tokio::test]
async fn sigterm_drains_and_exits_zero() {
    let harness = harness().await;
    let server = Server::start(&harness).await;
    let address = server.address;
    server.signal("TERM");
    let (status, stderr) = server.exit().await;
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_eq!(ready(address).await, None, "no longer accepting");
    assert_no_secret(&harness, &stderr);
}

#[tokio::test]
async fn sigint_drains_and_exits_zero() {
    let harness = harness().await;
    let server = Server::start(&harness).await;
    server.signal("INT");
    let (status, stderr) = server.exit().await;
    assert_eq!(status.code(), Some(0), "{stderr}");
    assert_no_secret(&harness, &stderr);
}
