//! HTTP serving and bounded graceful drain.

use std::{future::Future, time::Duration};

use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinHandle,
};

/// How long cancelled requests get to unwind and close their connections after the deadline.
const CANCEL_GRACE: Duration = Duration::from_secs(1);

/// Why serving ended unsuccessfully. Each variant makes the process exit nonzero.
#[derive(Debug, Error)]
pub enum ServeError {
    /// The server stopped although no stop was requested.
    #[error("HTTP server stopped without a signal")]
    UnexpectedStop,
    /// The HTTP server failed.
    #[error("HTTP server failed")]
    Server,
    /// The serving task panicked or was cancelled.
    #[error("HTTP task failed")]
    Task,
    /// Admitted requests were still running when the drain deadline passed; they were cancelled.
    #[error("shutdown deadline exceeded")]
    Deadline,
}

/// Serves `application` on `listener` until `stop` completes, with no deadline while serving.
///
/// When `stop` completes, the listener closes, so new connections are refused; idle keep-alive
/// connections close; and admitted requests get `deadline` to finish. Requests still running at the
/// deadline are cancelled: their handler futures are dropped, so an open transaction rolls back,
/// and the client receives the `503` `dependency-failure` Problem if its connection is still
/// writable, with `Cache-Control: no-store` on the audit proof routes. Nothing reads standard
/// input.
///
/// # Errors
///
/// [`ServeError::Deadline`] when requests are still running at the deadline, after cancelling
/// them; [`ServeError::UnexpectedStop`] when serving ends before `stop`; [`ServeError::Server`] or
/// [`ServeError::Task`] when the server itself fails.
///
/// # Cancellation
///
/// Dropping the returned future leaves the spawned server running; the composition root never
/// drops it before it completes.
pub async fn serve_until<S>(
    listener: TcpListener,
    application: Router,
    stop: S,
    deadline: Duration,
) -> Result<(), ServeError>
where
    S: Future<Output = ()> + Send + 'static,
{
    let (cancel_tx, cancel_rx) = watch::channel(false);
    // `no_store` wraps the cancellation so the shutdown 503 on an audit proof route is also
    // uncacheable; the router's own `no_store` cannot see a response produced outside it.
    let application = application
        .layer(middleware::from_fn_with_state(cancel_rx, cancellable))
        .layer(middleware::from_fn(crate::http::no_store));
    let (drain_tx, drain_rx) = oneshot::channel::<()>();
    let mut server: JoinHandle<std::io::Result<()>> = tokio::spawn(async move {
        axum::serve(listener, application)
            .with_graceful_shutdown(async move {
                let _ = drain_rx.await;
            })
            .await
    });
    tokio::pin!(stop);
    tokio::select! {
        finished = &mut server => {
            finish(finished)?;
            return Err(ServeError::UnexpectedStop);
        },
        () = &mut stop => {}
    }
    // The deadline starts only now; it never limits normal serving.
    let _ = drain_tx.send(());
    if let Ok(finished) = tokio::time::timeout(deadline, &mut server).await {
        return finish(finished);
    }
    // Axum runs each connection in its own task, so aborting the server task alone would leave
    // admitted handlers running. Cancel them, then give their connections a bounded grace to close.
    let _ = cancel_tx.send(true);
    if tokio::time::timeout(CANCEL_GRACE, &mut server)
        .await
        .is_err()
    {
        server.abort();
    }
    Err(ServeError::Deadline)
}

/// Runs a request unless the drain deadline cancels it first; cancellation drops the handler.
async fn cancellable(
    State(mut cancel): State<watch::Receiver<bool>>,
    request: Request,
    next: Next,
) -> Response {
    tokio::select! {
        response = next.run(request) => response,
        _ = cancel.wait_for(|cancelled| *cancelled) => crate::http::cancelled_at_shutdown(),
    }
}

fn finish(result: Result<std::io::Result<()>, tokio::task::JoinError>) -> Result<(), ServeError> {
    result
        .map_err(|_| ServeError::Task)?
        .map_err(|_| ServeError::Server)
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use axum::{
        extract::State,
        routing::{MethodRouter, get, post},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        sync::Notify,
    };

    use super::*;

    /// A toy application: `/quick` answers at once; `/held` answers only when released.
    #[derive(Clone, Default)]
    struct Gate {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        cancelled: Arc<AtomicBool>,
    }

    /// Records that a held handler was dropped before it finished.
    struct Unfinished {
        cancelled: Arc<AtomicBool>,
        finished: bool,
    }

    impl Drop for Unfinished {
        fn drop(&mut self) {
            if !self.finished {
                self.cancelled.store(true, Ordering::SeqCst);
            }
        }
    }

    /// A handler that answers only when released and records whether it was dropped first.
    async fn held(State(gate): State<Gate>) -> &'static str {
        let mut unfinished = Unfinished {
            cancelled: Arc::clone(&gate.cancelled),
            finished: false,
        };
        gate.entered.notify_one();
        gate.release.notified().await;
        unfinished.finished = true;
        "held"
    }

    fn application(gate: Gate) -> Router {
        let held_export: MethodRouter<Gate> = post(held);
        Router::new()
            .route("/quick", get(|| async { "quick" }))
            .route("/held", get(held))
            .route(crate::http::AUDIT_EXPORT_ROUTE, held_export)
            .with_state(gate)
    }

    struct Running {
        address: SocketAddr,
        stop: oneshot::Sender<()>,
        served: JoinHandle<Result<(), ServeError>>,
    }

    async fn start(gate: Gate, deadline: Duration) -> Running {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(serve_until(
            listener,
            application(gate),
            async move {
                let _ = stopped.await;
            },
            deadline,
        ));
        Running {
            address,
            stop,
            served,
        }
    }

    /// Sends one request and returns the response body, or `None` when the connection fails.
    async fn request(address: SocketAddr, path: &str) -> Option<String> {
        response(address, path)
            .await?
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
    }

    /// Sends one request and returns the whole response, or `None` when the connection fails.
    async fn response(address: SocketAddr, path: &str) -> Option<String> {
        send(address, "GET", path).await
    }

    /// Sends one bodiless request with `method` and returns the whole response, or `None` when
    /// the connection fails.
    async fn send(address: SocketAddr, method: &str, path: &str) -> Option<String> {
        let mut stream = TcpStream::connect(address).await.ok()?;
        stream
            .write_all(
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .ok()?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await.ok()?;
        Some(response)
    }

    #[tokio::test]
    async fn serves_past_the_drain_deadline_until_stopped() {
        let running = start(Gate::default(), Duration::from_millis(50)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            request(running.address, "/quick").await.as_deref(),
            Some("quick")
        );
        assert!(!running.served.is_finished());
        running.stop.send(()).expect("stop");
        assert!(matches!(running.served.await, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn stop_drains_an_admitted_request_then_returns_ok() {
        let gate = Gate::default();
        let running = start(gate.clone(), Duration::from_secs(5)).await;
        let held = tokio::spawn(request(running.address, "/held"));
        gate.entered.notified().await;
        running.stop.send(()).expect("stop");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !running.served.is_finished(),
            "waits for the admitted request"
        );
        gate.release.notify_one();
        assert_eq!(held.await.expect("request task").as_deref(), Some("held"));
        assert!(matches!(running.served.await, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn stop_refuses_new_connections() {
        let gate = Gate::default();
        let running = start(gate.clone(), Duration::from_secs(5)).await;
        let held = tokio::spawn(request(running.address, "/held"));
        gate.entered.notified().await;
        running.stop.send(()).expect("stop");
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Draining: the admitted request is still open, but nothing new is accepted.
        assert_eq!(request(running.address, "/quick").await, None);
        gate.release.notify_one();
        assert_eq!(held.await.expect("request task").as_deref(), Some("held"));
        assert!(matches!(running.served.await, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn drain_past_the_deadline_cancels_and_fails() {
        let gate = Gate::default();
        let running = start(gate.clone(), Duration::from_millis(100)).await;
        let held = tokio::spawn(response(running.address, "/held"));
        gate.entered.notified().await;
        running.stop.send(()).expect("stop");
        assert!(matches!(
            running.served.await,
            Ok(Err(ServeError::Deadline))
        ));
        // The admitted handler was dropped, not left running, and never answered normally.
        assert!(gate.cancelled.load(Ordering::SeqCst));
        let answered = tokio::time::timeout(Duration::from_secs(5), held)
            .await
            .expect("the cancelled connection closes")
            .expect("request task")
            .expect("the cancelled request is answered");
        let (head, body) = answered.split_once("\r\n\r\n").expect("response head");
        let mut lines = head.lines();
        assert_eq!(
            lines.next(),
            Some("HTTP/1.1 503 Service Unavailable"),
            "{head}"
        );
        assert!(
            lines.any(|line| line.eq_ignore_ascii_case("content-type: application/json")),
            "{head}"
        );
        assert_eq!(body, r#"{"category":"dependency-failure"}"#);
    }

    #[tokio::test]
    async fn drain_deadline_cancel_of_an_audit_export_is_uncacheable() {
        let gate = Gate::default();
        let running = start(gate.clone(), Duration::from_millis(100)).await;
        let held = tokio::spawn(send(
            running.address,
            "POST",
            crate::http::AUDIT_EXPORT_ROUTE,
        ));
        gate.entered.notified().await;
        running.stop.send(()).expect("stop");
        assert!(matches!(
            running.served.await,
            Ok(Err(ServeError::Deadline))
        ));
        assert!(gate.cancelled.load(Ordering::SeqCst));
        let answered = tokio::time::timeout(Duration::from_secs(5), held)
            .await
            .expect("the cancelled connection closes")
            .expect("request task")
            .expect("the cancelled request is answered");
        let (head, body) = answered.split_once("\r\n\r\n").expect("response head");
        assert_eq!(
            head.lines().next(),
            Some("HTTP/1.1 503 Service Unavailable"),
            "{head}"
        );
        assert!(
            head.lines()
                .any(|line| line.eq_ignore_ascii_case("cache-control: no-store")),
            "{head}"
        );
        assert_eq!(body, r#"{"category":"dependency-failure"}"#);
    }

    #[tokio::test]
    async fn drain_deadline_cancel_off_the_proof_routes_keeps_its_caching() {
        let gate = Gate::default();
        let running = start(gate.clone(), Duration::from_millis(100)).await;
        let held = tokio::spawn(response(running.address, "/held"));
        gate.entered.notified().await;
        running.stop.send(()).expect("stop");
        assert!(matches!(
            running.served.await,
            Ok(Err(ServeError::Deadline))
        ));
        let answered = tokio::time::timeout(Duration::from_secs(5), held)
            .await
            .expect("the cancelled connection closes")
            .expect("request task")
            .expect("the cancelled request is answered");
        let (head, _) = answered.split_once("\r\n\r\n").expect("response head");
        assert!(
            !head
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("cache-control:")),
            "{head}"
        );
    }
}
