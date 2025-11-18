use clap::Parser;
use std::net::SocketAddr;
use tapp_service::{
    auth::ApiKeyInterceptor, config::TappConfig, init_tracing, TappServiceImpl, TappServiceServer,
    VERSION,
};
use tonic::transport::Server;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "tapp-server")]
#[command(about = "TAPP gRPC Server", version = VERSION)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/tapp/config.toml")]
    config: String,

    /// Bind address (overrides config)
    #[arg(short, long)]
    bind: Option<String>,

    /// Enable verbose logging (overrides config)
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Step 1: Load configuration first (before initializing logging)
    let mut config = match TappConfig::load(args.config.clone()) {
        Ok(config) => {
            // Use println because tracing is not initialized yet
            println!("✓ Configuration loaded from: {}", args.config);
            config
        }
        Err(e) => {
            println!("⚠ Failed to load config from {}: {}", args.config, e);
            println!("Using default configuration");
            TappConfig::default()
        }
    };

    // Step 2: Override config with command-line args if provided
    if args.verbose {
        config.logging.level = "debug".to_string();
    }

    // Step 3: Initialize tracing with config
    init_tracing(&config.logging)?;

    info!("🚀 Starting TDX TAPP Service Server");
    info!("Version: {}", VERSION);
    info!("Configuration loaded from: {}", args.config);
    info!(
        logging_level = %config.logging.level,
        logging_format = %config.logging.format,
        logging_file = ?config.logging.file_path,
        "Logging initialized"
    );

    // Step 4: Determine bind address
    let bind_address = args
        .bind
        .unwrap_or_else(|| config.server.bind_address.clone());

    let addr: SocketAddr = bind_address
        .parse()
        .map_err(|e| format!("Invalid bind address '{}': {}", bind_address, e))?;

    info!("Binding to address: {}", addr);

    // Step 5: Initialize service
    let service = match TappServiceImpl::new(config.clone()).await {
        Ok(service) => {
            info!("✓ TAPP service initialized successfully");
            service
        }
        Err(e) => {
            error!("✗ Failed to initialize TAPP service: {}", e);
            std::process::exit(1);
        }
    };

    // Step 6: Create API key interceptor
    let api_key_config = config.server.api_key.clone();
    let interceptor = ApiKeyInterceptor::new(api_key_config.clone());

    // Log API key configuration status
    if let Some(ref api_config) = api_key_config {
        if api_config.enabled {
            info!(
                "🔐 API key authentication enabled with {} key(s)",
                api_config.keys.len()
            );
            if api_config.protected_methods.is_empty() {
                info!("   All methods require API key authentication");
            } else {
                info!(
                    "   Protected methods: {}",
                    api_config.protected_methods.join(", ")
                );
            }
        } else {
            info!("🔓 API key authentication disabled");
        }
    } else {
        info!("🔓 API key authentication not configured");
    }

    // Step 7: Create gRPC server with interceptor
    let server = Server::builder()
        .add_service(TappServiceServer::with_interceptor(service, move |req| {
            interceptor.clone().intercept(req)
        }))
        .serve(addr);

    info!("🌐 TAPP gRPC server starting on {}", addr);

    // Step 8: Handle shutdown gracefully
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
