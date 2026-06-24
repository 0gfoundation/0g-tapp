use attestation_agent::AttestationAgent;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tapp_service::{
    auth_layer::AuthLayer, config::TappConfig, init_tracing, permission::PermissionManager,
    TappServiceImpl, TappServiceServer, VERSION,
};
use tonic::transport::Server;
use tower::ServiceBuilder;
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

    info!("🚀 Starting TDX TAPP Service Server v{}", VERSION);
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

    // Step 5: Initialize PermissionManager if configured
    let permission_manager = if let Some(ref perm_config) = config.server.permission {
        if perm_config.enabled {
            info!("🔐 Permission-based authentication enabled");
            info!("   Tapp owner: {}", perm_config.owner_address);

            let pm = Arc::new(PermissionManager::new(perm_config.owner_address.clone()));

            // Initialize whitelist with addresses from config
            if !perm_config.initial_whitelist.is_empty() {
                info!(
                    "   Initializing whitelist with {} address(es)",
                    perm_config.initial_whitelist.len()
                );
                for addr in &perm_config.initial_whitelist {
                    pm.add_to_whitelist(addr.clone()).await.ok();
                    info!("      - {}", addr);
                }
            }

            Some(pm)
        } else {
            info!("🔓 Permission-based authentication disabled");
            None
        }
    } else {
        info!("🔓 Permission-based authentication not configured");
        None
    };

    // Step 6: Initialize AttestationAgent and MeasurementService
    // Ensure AA config file exists
    if let Some(ref aa_config_path) = config.boot.aa_config_path {
        tapp_service::boot::BootService::ensure_aa_config(aa_config_path)
            .expect("Failed to ensure AA config");
    }
    let mut aa = AttestationAgent::new(config.boot.aa_config_path.as_deref())
        .expect("Failed to create AttestationAgent");
    aa.init()
        .await
        .expect("Failed to initialize AttestationAgent");

    let measurement_service = Arc::new(tapp_service::measurement_service::MeasurementService::new(
        Arc::new(tokio::sync::Mutex::new(aa)),
    ));
    info!(
        "✓ Detected TEE type: {:?}",
        measurement_service.get_tee_type().await
    );

    // Step 7: Initialize service with PermissionManager and MeasurementService
    let service = match TappServiceImpl::new(
        config.clone(),
        permission_manager.clone(),
        measurement_service,
    )
    .await
    {
        Ok(service) => {
            info!("✓ TAPP service initialized successfully");
            service
        }
        Err(e) => {
            error!("✗ Failed to initialize TAPP service: {}", e);
            std::process::exit(1);
        }
    };

    // Step 8: Create gRPC server with auth layer
    let auth_layer = if let Some(pm) = permission_manager {
        AuthLayer::with_permission_manager(pm)
    } else {
        AuthLayer::new(config.server.permission.clone())
    };

    let layer = ServiceBuilder::new().layer(auth_layer).into_inner();

    let server = Server::builder()
        .layer(layer)
        .add_service(TappServiceServer::new(service))
        .serve(addr);

    info!("🌐 TAPP gRPC server listening on {}", addr);

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
