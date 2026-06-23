// Minimal library for tapp-cli: only proto, onchain, app_key (sign/verify), and error types.
// Proto definitions are pre-generated (proto_gen.rs) so no protoc is needed at build time.

pub mod error;
pub mod onchain;
pub mod app_key;

pub mod proto {
    include!("proto_gen.rs");
}

pub use proto::{
    tapp_service_client::TappServiceClient,
    *,
};
