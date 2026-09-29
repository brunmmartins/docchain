use std::{io::Write as _, process::ExitCode, sync::Arc};

use docchain_server::{
    DocchainService, HttpConfig, ServiceError,
    config::{Settings, SettingsError},
    diagnostics::{
        Diagnostics, EXIT_FLUSH_LIMIT, Setting, SettingReason, StartupFailure, StartupStep,
    },
    router_with_diagnostics,
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

impl StartupError {
    /// The closed startup-failure record for a failure before the listener bound; none once
    /// serving has begun.
    fn failure(&self) -> Option<StartupFailure> {
        Some(match self {
            Self::Configuration(error) => StartupFailure::configuration(
                Setting::new(error.key()),
                SettingReason::new(error.reason()),
            ),
            Self::Initialization(ServiceError::Initialization(step)) => {
                StartupFailure::at(StartupStep::new(step))
            }
            Self::Initialization(_) => StartupFailure::at(StartupStep::ServiceInitialization),
            Self::Listener => StartupFailure::at(StartupStep::HttpListener),
            Self::Signal => StartupFailure::at(StartupStep::SignalListener),
            Self::Serve(_) => return None,
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let diagnostics = Diagnostics::start();
    let code = match run(&diagnostics).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(failure) = error.failure() {
                diagnostics.startup_failed(failure);
            }
            write_stderr(&error);
            ExitCode::FAILURE
        }
    };
    // Bounded: records still queued after the limit are lost.
    diagnostics.flush(EXIT_FLUSH_LIMIT);
    code
}

fn write_stderr(text: &impl std::fmt::Display) {
    let line = format!("docchain-server: {text}\n");
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// Diagnostics (already started), settings, database checks, adapters, the document-store lease
/// and sweep, the sweep's report line, signal listeners, then the TCP listener.
async fn run(diagnostics: &Diagnostics) -> Result<(), StartupError> {
    let settings = Settings::from_env()?;
    let diagnostics = diagnostics.clone().with_spans(settings.diagnostics.spans);
    let service = Arc::new(DocchainService::compose(&settings).await?);
    // One line with counts or a skip reason only.
    write_stderr(&service.sweep_report());
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| StartupError::Signal)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| StartupError::Signal)?;
    let listener = tokio::net::TcpListener::bind(settings.http.bind)
        .await
        .map_err(|_| StartupError::Listener)?;
    let application = router_with_diagnostics(
        service,
        HttpConfig {
            request_timeout: settings.http.request_timeout,
            max_in_flight: settings.http.max_in_flight,
        },
        diagnostics,
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
