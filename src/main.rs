use attestation_agent::AttestationAgent;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tapp_server::{
    auth_layer::AuthLayer, config::TappConfig, init_tracing, permission::PermissionManager,
    TappServiceImpl, TappServiceServer, VERSION,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
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

    // Step 4: Determine bind address (used when unix_socket_path is not set)
    let bind_address = args
        .bind
        .unwrap_or_else(|| config.server.bind_address.clone());

    // Step 5: Initialize PermissionManager if configured. The owner is NOT
    // set here — it is established after the MeasurementService is up (Step
    // 6.5), so the claim can be extended into the runtime measurement.
    let permission_manager = if let Some(ref perm_config) = config.server.permission {
        if perm_config.enabled {
            info!("🔐 Permission-based authentication enabled");
            let pm = Arc::new(
                PermissionManager::new(None)
                    .with_owner_state_path(perm_config.owner_state_path.clone()),
            );
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
        tapp_server::boot::BootService::ensure_aa_config(aa_config_path)
            .expect("Failed to ensure AA config");
    }
    let mut aa = AttestationAgent::new(config.boot.aa_config_path.as_deref())
        .expect("Failed to create AttestationAgent");
    aa.init()
        .await
        .expect("Failed to initialize AttestationAgent");

    let measurement_service = Arc::new(tapp_server::measurement_service::MeasurementService::new(
        Arc::new(tokio::sync::Mutex::new(aa)),
    ));
    info!(
        "✓ Detected TEE type: {:?}",
        measurement_service.get_tee_type().await
    );

    // Step 6.5: Establish the tapp owner (config / persisted claim / unclaimed).
    // Also passes chain/kbs from config so the startup claim_config measurement
    // includes the full runtime configuration baked into the image.
    if let Some(ref pm) = permission_manager {
        let config_owner = config
            .server
            .permission
            .as_ref()
            .and_then(|p| p.owner_address.as_deref());
        let chain_rpc_url = config
            .chain
            .as_ref()
            .map(|c| c.rpc_url.as_str())
            .unwrap_or("");
        let chain_contract = config
            .chain
            .as_ref()
            .map(|c| c.contract_address.as_str())
            .unwrap_or("");
        let kbs_urls: Vec<String> = config
            .kbs
            .as_ref()
            .map(|k| k.node_urls.clone())
            .unwrap_or_default();

        match tapp_server::establish_owner_at_startup(
            pm,
            &measurement_service,
            config_owner,
            chain_rpc_url,
            chain_contract,
            &kbs_urls,
        )
        .await
        {
            Ok(Some(owner)) => info!("   Tapp owner: {}", owner),
            Ok(None) => info!(
                "   Tapp owner: ⏳ UNCLAIMED — first valid signer of the \
                 ClaimConfig RPC becomes the owner (tapp-cli claim-config)"
            ),
            Err(e) => {
                error!("✗ Failed to establish tapp owner: {}", e);
                std::process::exit(1);
            }
        }
    }

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

    let grpc = TappServiceServer::new(service);

    // Always serve TCP on bind_address. When unix_socket_path is set, ADDITIONALLY
    // serve the same service on a Unix domain socket — so same-host clients (e.g. a
    // Docker container fetching its key via get-app-secret-key) can use the socket
    // while remote clients keep using TCP :50051. Both listeners share the service;
    // each keeps its native connect-info, so remote_addr()-based local-only checks
    // behave correctly (TCP => Some(ip), Unix socket => None).
    let addr: SocketAddr = bind_address
        .parse()
        .map_err(|e| format!("Invalid bind address '{}': {}", bind_address, e))?;

    info!("🌐 TAPP gRPC server listening on {}", addr);
    let tcp_server = Server::builder()
        .layer(layer.clone())
        .add_service(grpc.clone())
        .serve(addr);

    if let Some(ref socket_path) = config.server.unix_socket_path {
        // Clean up stale socket file from a previous run
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }

        // Ensure parent directory exists with restrictive permissions
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(parent) {
                    let mut perms = metadata.permissions();
                    // 0750, not the 0700 this used to force. A directory a non-root process
                    // cannot traverse makes the socket's own mode irrelevant — it could be
                    // 0666 and still be unreachable — so tightening here silently undid any
                    // attempt to let a hardened container connect. It also contradicted the
                    // systemd unit, which creates this directory 0755 with a comment saying
                    // app containers bind-mount it.
                    perms.set_mode(0o750);
                    std::fs::set_permissions(parent, perms)?;
                }
            }
        }

        let uds = UnixListener::bind(socket_path)?;

        // Who may open the socket. The mode is not the security boundary — anything the
        // socket is mounted into can read every app's key material, so the mount is — but
        // it decides who else on the host can reach it. 0600 made that "only root", which
        // forced every consumer to run its container as root and give up real hardening
        // for no gain. See config::unix_socket_mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = u32::from_str_radix(config.server.unix_socket_mode.trim_start_matches("0o"), 8)
                .map_err(|_| {
                    format!(
                        "server.unix_socket_mode must be octal like \"0660\", got {:?}",
                        config.server.unix_socket_mode
                    )
                })?;
            if let Ok(metadata) = std::fs::metadata(socket_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(mode);
                std::fs::set_permissions(socket_path, perms)?;
            }
            if let Some(gid) = config.server.unix_socket_gid {
                // Only the group changes; the owner stays root so the server keeps
                // exclusive write of the path itself.
                let c_path = std::ffi::CString::new(socket_path.as_os_str().as_encoded_bytes())
                    .map_err(|e| format!("socket path: {e}"))?;
                // SAFETY: a valid NUL-terminated path and real ids; chown reports failure
                // through its return value rather than by any effect on this process.
                let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
                if rc != 0 {
                    return Err(format!(
                        "cannot set socket group to {}: {}",
                        gid,
                        std::io::Error::last_os_error()
                    )
                    .into());
                }
            }
            info!(
                socket_path = %socket_path.display(),
                mode = %format!("{:04o}", mode & 0o7777),
                gid = ?config.server.unix_socket_gid,
                "Socket permissions applied"
            );
        }

        info!(
            socket_path = %socket_path.display(),
            "🌐 TAPP gRPC server also listening on Unix socket"
        );

        let uds_server = Server::builder()
            .layer(layer)
            .add_service(grpc)
            .serve_with_incoming(UnixListenerStream::new(uds));

        tokio::select! {
            result = tcp_server => {
                if let Err(e) = result {
                    error!("Server error (tcp): {}", e);
                    std::process::exit(1);
                }
            }
            result = uds_server => {
                if let Err(e) = result {
                    error!("Server error (unix socket): {}", e);
                    std::process::exit(1);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, stopping server");
            }
        }

        // Clean up socket file on shutdown
        let _ = std::fs::remove_file(socket_path);
    } else {
        tokio::select! {
            result = tcp_server => {
                if let Err(e) = result {
                    error!("Server error: {}", e);
                    std::process::exit(1);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, stopping server");
            }
        }
    }

    info!("TAPP server shutdown complete");
    Ok(())
}
