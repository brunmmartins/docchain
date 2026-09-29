//! Docchain composition root and local adapters.

pub mod config;
pub mod crypto;
pub mod diagnostics;
mod harness;
mod http;
#[doc(hidden)]
pub mod migrator;
mod providers;
#[doc(hidden)]
pub mod serve;
mod store;

pub use docchain_application::{Actor, Credential, SendCopyCommand};
#[cfg(feature = "test-support")]
pub use harness::{DatabaseFixture, DemoHarness, StartOptions, StateStats};
pub use harness::{DocchainService, ServiceError};
pub use http::{HttpConfig, router, router_with_diagnostics};
#[cfg(feature = "test-support")]
pub use store::{PauseGate, ScanFault, SweepBounds};
