//! Applies Docchain's embedded forward migrations as the migration owner, then exits.
//!
//! It takes no arguments and never reads standard input. Exit codes: 0 when the schema is
//! current, 1 on a bounded failure, and 2 when given any argument.

use std::process::ExitCode;

use docchain_server::{config::MigrationSettings, migrator};

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        eprintln!("docchain-migrate: takes no arguments");
        return ExitCode::from(2);
    }
    let settings = match MigrationSettings::from_env() {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("docchain-migrate: {error}");
            return ExitCode::FAILURE;
        }
    };
    match migrator::run(&settings).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(step) => {
            eprintln!("docchain-migrate: {step}");
            ExitCode::FAILURE
        }
    }
}
