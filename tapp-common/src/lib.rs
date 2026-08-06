//! Shared library for tapp-cli and tapp-server.
//! Contains proto types, onchain operations, app key, verify, and error types.
//! No TEE/Docker/system dependencies — safe to compile on macOS.

pub mod error;
pub mod onchain;
pub mod app_key;
pub mod report_data;
pub mod verify;
pub mod compat;

pub mod proto {
    tonic::include_proto!("tapp_service");
}

pub mod as_proto {
    tonic::include_proto!("attestation");
}

pub use proto::tapp_service_client::TappServiceClient;
pub use error::{TappError, TappResult};
