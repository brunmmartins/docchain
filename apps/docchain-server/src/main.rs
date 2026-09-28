use std::{process::ExitCode, sync::Arc};

use docchain_server::{
    DocchainService, HttpConfig, ServiceError,
    config::{Settings, SettingsError},
    router,
};
use thiserror::Error;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Debug, Error)]
enum StartupError {
    #[error(transparent)]
    Configuration(#[from] SettingsError),
    #[error(transparent)]
    Initialization(#[from] ServiceError),
    #[error("HTTP listener failed")]
    Listener,
    #[error("signal listener failed")]
    Signal,
    #[error(transparent)]
    Serve(#[from] docchain_server::serve::ServeError),
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("docchain-server: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Settings, database checks, adapters, the document-store lease and sweep, the sweep's report
/// line, signal listeners, then the TCP listener.
async fn run() -> Result<(), StartupError> {
    let settings = Settings::from_env()?;
    let service = Arc::new(DocchainService::compose(&settings).await?);
    // One line with counts or a skip reason only.
    eprintln!("docchain-server: {}", service.sweep_report());
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| StartupError::Signal)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| StartupError::Signal)?;
    let listener = tokio::net::TcpListener::bind(settings.http.bind)
        .await
        .map_err(|_| StartupError::Listener)?;
    let application = router(
        service,
        HttpConfig {
            request_timeout: settings.http.request_timeout,
            max_in_flight: settings.http.max_in_flight,
        },
    );

    docchain_server::serve::serve_until(
        listener,
        application,
        async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        },
        settings.http.shutdown_timeout,
    )
    .await?;
    Ok(())
}
