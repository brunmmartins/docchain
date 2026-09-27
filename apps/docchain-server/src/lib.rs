//! Docchain composition root and local adapters.

pub mod config;
pub mod crypto;
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
pub use harness::{DatabaseFixture, DemoHarness, StateStats};
pub use harness::{DocchainService, ServiceError};
pub use http::{HttpConfig, router};
