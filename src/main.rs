use clap::Parser;
use std::net::SocketAddr;
use tapp_service::config::TappConfig;
use tapp_service::proto::tapp_service_server::TappServiceServer;
use tapp_service::TappServiceImpl;
use tonic::transport::Server;
use tracing::{error, info, warn};

/// TDX TAPP Service - Rust Implementation
#[derive(Parser)]
#[command(name = "tapp-server")]
#[command(about = "TDX Trusted Application Platform Service")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Server bind address
    #[arg(short, long, default_value = "0.0.0.0:50051")]
    bind: String,

    /// Enable verbose logging
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    info!("Starting TDX TAPP Service Server");
    info!("Version: {}", tapp_service::VERSION);

    // Load configuration
    let config = match TappConfig::load(args.config.clone()) {
        Ok(config) => {
            info!("Configuration loaded from: {}", args.config);
            config
        }
        Err(e) => {
            warn!("Failed to load config from {}: {}", args.config, e);
            info!("Using default configuration");
            TappConfig::default()
        }
    };

    // Parse bind address
    let addr: SocketAddr = args
        .bind
        .parse()
        .map_err(|e| format!("Invalid bind address '{}': {}", args.bind, e))?;

    info!("Binding to address: {}", addr);

    // Initialize service
    let service = match TappServiceImpl::new(config).await {
        Ok(service) => {
            info!("TAPP service initialized successfully");
            service
        }
        Err(e) => {
            error!("Failed to initialize TAPP service: {}", e);
            std::process::exit(1);
        }
    };

    // Create gRPC server
    let server = Server::builder()
        .add_service(TappServiceServer::new(service))
        .serve(addr);

    info!("TAPP gRPC server starting on {}", addr);

    // Handle shutdown gracefully
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal, stopping server");
        }
    }

    info!("TAPP server shutdown complete");
    Ok(())
}
