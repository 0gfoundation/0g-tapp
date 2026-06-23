use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tapp_service::proto::{
    tapp_service_client::TappServiceClient, AddToWhitelistRequest, DockerLoginRequest,
    DockerLogoutRequest, GetAppContainerStatusRequest, GetAppInfoRequest, GetAppKeyRequest,
    GetAppLogsRequest, GetAppSecretKeyRequest, GetEvidenceRequest, GetSecretResourceRequest,
    GetServiceLogsRequest, GetServiceStatusRequest, GetTappInfoRequest, GetTaskStatusRequest,
    ListAppsRequest, ListWhitelistRequest, MountFile, PruneImagesRequest, RemoveFromWhitelistRequest,
    StartAppRequest, StartServiceRequest, StopAppRequest, StopServiceRequest, WithdrawBalanceRequest,
};
use tonic::{metadata::MetadataValue, Request};

#[derive(Parser)]
#[command(name = "tapp-cli")]
#[command(about = "TAPP Service CLI - Interact with TAPP gRPC server", long_about = None)]
#[command(version)]
struct Cli {
    /// gRPC server address
    #[arg(short, long, default_value = "http://127.0.0.1:50051", global = true)]
    server: String,

    /// Private key for authentication (can also use TAPP_PRIVATE_KEY env var)
    #[arg(short = 'k', long, global = true)]
    private_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start an application with Docker Compose
    ///
    /// This command automatically extracts and uploads local files referenced
    /// in the compose file's volumes section (e.g., ./config.toml:/app/config.toml).
    StartApp {
        /// Path to Docker Compose file
        #[arg(short = 'f', long)]
        compose_file: PathBuf,

        /// Application ID
        #[arg(short, long)]
        app_id: String,
    },

    /// Stop a running application
    StopApp {
        /// Application ID to stop
        #[arg(short, long)]
        app_id: String,
    },

    /// Get task status
    GetTaskStatus {
        /// Task ID
        #[arg(short, long)]
        task_id: String,
    },

    /// Get application information
    GetAppInfo {
        /// Application ID
        #[arg(short, long)]
        app_id: String,
    },

    /// Verify an app. Chain mode (with --contract + --rpc-url): discover nodes on-chain,
    /// fetch each node's evidence, verify the quote via CoCo-AS, and reconcile against the
    /// chain. Direct mode (no --contract, uses --server): verify one node's evidence + quote
    /// and show what it attests, without on-chain reconciliation (for un-registered apps).
    VerifyApp {
        /// Application ID
        #[arg(long)]
        app_id: String,
        /// EVM RPC URL (chain mode)
        #[arg(long)]
        rpc_url: Option<String>,
        /// TappRegistry contract address 0x… (chain mode)
        #[arg(long)]
        contract: Option<String>,
        /// CoCo Attestation Service gRPC endpoint (host:port)
        #[arg(long, default_value = "47.237.201.184:50004")]
        as_endpoint: String,
    },
    /// List all apps currently on the server
    ListApps,

    /// Get application logs
    GetAppLogs {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Number of lines to retrieve (default: 100)
        #[arg(short = 'n', long, default_value = "100")]
        lines: i32,

        /// Specific service name
        #[arg(long)]
        service: Option<String>,
    },

    /// Get application container status
    GetAppContainerStatus {
        /// Application ID
        #[arg(short, long)]
        app_id: String,
    },

    /// Get attestation evidence for an application
    GetEvidence {
        /// Application ID
        #[arg(short, long)]
        app_id: String,
    },

    /// Get application public key
    GetAppKey {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Key type (default: ethereum)
        #[arg(short = 't', long, default_value = "ethereum")]
        key_type: String,

        /// Use X25519 key pair
        #[arg(long)]
        x25519: bool,
    },

    /// Get application secret key (local access only)
    GetAppSecretKey {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Output in JSON format
        #[arg(long)]
        json: bool,

        /// Use X25519 key pair
        #[arg(long)]
        x25519: bool,
    },

    /// Get secret resource from KMS (local access only)
    GetSecretResource {
        /// Application ID
        #[arg(short, long)]
        app_id: String,
    },

    /// Start a specific service within an app
    StartService {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Service name
        #[arg(long)]
        service_name: String,

        /// Pull latest image before starting
        #[arg(long)]
        pull: bool,
    },

    /// Stop a specific service within an app
    StopService {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Service name
        #[arg(long)]
        service_name: String,
    },

    /// Add address to whitelist (owner only)
    AddToWhitelist {
        /// EVM address to add
        #[arg(short, long)]
        address: String,
    },

    /// Remove address from whitelist (owner only)
    RemoveFromWhitelist {
        /// EVM address to remove
        #[arg(short, long)]
        address: String,
    },

    /// List all whitelisted addresses
    ListWhitelist,

    /// Login to Docker registry
    DockerLogin {
        /// Registry URL (default: docker.io)
        #[arg(short, long)]
        registry: Option<String>,

        /// Username
        #[arg(short, long)]
        username: String,

        /// Password (or use DOCKER_PASSWORD env var)
        #[arg(short, long)]
        password: String,
    },

    /// Logout from Docker registry
    DockerLogout {
        /// Registry URL (default: docker.io)
        #[arg(short, long)]
        registry: Option<String>,
    },

    /// Prune unused Docker images
    PruneImages {
        /// Remove all unused images, not just dangling ones
        #[arg(long)]
        all: bool,
    },

    /// Get TAPP service information
    GetTappInfo,

    /// Get service status and health information
    GetServiceStatus {
        /// Number of recent log lines from journalctl
        #[arg(short = 'n', long, default_value = "50")]
        log_lines: i32,
    },

    /// Get service logs
    GetServiceLogs {
        /// Log file name (leave empty to list all files)
        #[arg(short = 'f', long)]
        file_name: Option<String>,

        /// Number of lines to retrieve
        #[arg(short = 'n', long, default_value = "100")]
        lines: i32,

        /// Download full file content
        #[arg(long)]
        download_full: bool,
    },

    /// Withdraw balance from app to owner
    WithdrawBalance {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// Chain ID
        #[arg(long)]
        chain_id: u64,

        /// Custom recipient address (defaults to tapp owner)
        #[arg(long)]
        recipient: Option<String>,
    },

    /// Sign a message using a private key
    SignMessage {
        /// Private key (32 bytes hex)
        #[arg(short = 'k', long)]
        private_key: String,

        /// Message to sign (will be treated as UTF-8 string)
        #[arg(short, long)]
        message: String,
    },

    /// Verify a signature using a public key
    VerifySignature {
        /// Public key (64 bytes hex)
        #[arg(short = 'p', long)]
        public_key: String,

        /// Message that was signed
        #[arg(short, long)]
        message: String,

        /// Signature (hex)
        #[arg(long)]
        signature: String,
    },


    /// Register app on-chain after starting it.
    /// Fetches compose/volume/image hashes and signerAddress from --server, registers them.
    /// The --server URL is also recorded on-chain as the node's evidence URL.
    RegisterOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,

        /// Stake amount in wei (must be >= minStakeAmount)
        #[arg(long)]
        stake_wei: u128,
    },

    /// Update app hashes on-chain after redeployment (fetches updated hashes from --server)
    UpdateOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,
    },

    /// Add a node to an existing on-chain app.
    /// Connect to the new node via --server to fetch its signerAddress automatically.
    /// The --server URL is recorded on-chain as the node's evidence URL.
    AddNodeOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,

        /// Stake amount in wei (must be >= minStakeAmount)
        #[arg(long)]
        stake_wei: u128,

        /// Signer address of the new node (optional; fetched from --server if not set)
        #[arg(long)]
        signer_address: Option<String>,

        /// TEE URL of the new node (optional; defaults to --server URL)
        #[arg(long)]
        tee_url: Option<String>,
    },

    /// Remove a node from an on-chain app (starts the stake lock period).
    /// Connect to the node via --server to fetch its signerAddress automatically.
    RemoveNodeOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,

        /// Signer address to remove (skips fetching from --server; useful when node is unreachable)
        #[arg(long)]
        signer_address: Option<String>,
    },

    /// Update a node: replace old signer with new signer atomically (transfers stake).
    /// New signer is fetched from --server unless --new-signer is specified.
    UpdateNodeOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,

        /// Old signer address to replace (optional; fetched from --server if not set)
        #[arg(long)]
        old_signer: Option<String>,

        /// New signer address (optional; fetched from --server if not set)
        #[arg(long)]
        new_signer: Option<String>,

        /// TEE URL for the new node (optional; defaults to --server URL)
        #[arg(long)]
        tee_url: Option<String>,
    },

    /// Withdraw a removed node's stake after the lock period elapses.
    /// Requires --signer-address because the node may already be stopped.
    /// Withdraw all matured locked stake entries for the caller.
    Withdraw {
        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,
    },

    /// Authorize a sibling contract to call invalidateAcks for this app.
    /// Only the app owner may authorize. Idempotent: re-authorizing has no effect.
    AuthorizeInvalidatorOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,

        /// Invalidator address to authorize (0x...; typically a sibling contract)
        #[arg(short, long)]
        invalidator: String,
    },

    /// Revoke a previously-authorized invalidator for this app.
    /// Only the app owner may revoke. Idempotent: revoking a non-authorized address is a no-op.
    RevokeInvalidatorOnchain {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Ethereum RPC URL
        #[arg(short, long)]
        rpc_url: String,

        /// TappRegistry contract address (0x...)
        #[arg(short, long)]
        contract: String,

        /// Invalidator address to revoke (0x...)
        #[arg(short, long)]
        invalidator: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli = Cli::parse();

    // Handle environment variables for private_key if not provided
    if cli.private_key.is_none() {
        if let Ok(env_key) = std::env::var("TAPP_PRIVATE_KEY") {
            cli.private_key = Some(env_key);
        }
    }

    match cli.command {
        Commands::StartApp {
            compose_file,
            app_id,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            start_app(&cli.server, compose_file, app_id, private_key).await?;
        }
        Commands::StopApp { app_id } => {
            let private_key = require_private_key(&cli.private_key)?;
            stop_app(&cli.server, app_id, private_key).await?;
        }
        Commands::GetTaskStatus { task_id } => {
            get_task_status(&cli.server, task_id).await?;
        }
        Commands::GetAppInfo { app_id } => {
            get_app_info(&cli.server, app_id).await?;
        }
        Commands::VerifyApp { app_id, rpc_url, contract, as_endpoint } => {
            verify_app_cmd(&cli.server, &app_id, rpc_url, contract, &as_endpoint).await?;
        }
        Commands::ListApps => {
            list_apps(&cli.server).await?;
        }
        Commands::GetAppLogs {
            app_id,
            lines,
            service,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            get_app_logs(&cli.server, app_id, lines, service, private_key).await?;
        }
        Commands::GetAppContainerStatus { app_id } => {
            let private_key = require_private_key(&cli.private_key)?;
            get_app_container_status(&cli.server, app_id, private_key).await?;
        }
        Commands::GetEvidence { app_id } => {
            get_evidence(&cli.server, app_id).await?;
        }
        Commands::GetAppKey {
            app_id,
            key_type,
            x25519,
        } => {
            get_app_key(&cli.server, app_id, key_type, x25519).await?;
        }
        Commands::GetAppSecretKey {
            app_id,
            json,
            x25519,
        } => {
            get_app_secret_key(&cli.server, app_id, json, x25519).await?;
        }
        Commands::GetSecretResource { app_id } => {
            get_secret_resource(&cli.server, app_id).await?;
        }
        Commands::StartService {
            app_id,
            service_name,
            pull,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            start_service(&cli.server, app_id, service_name, pull, private_key).await?;
        }
        Commands::StopService {
            app_id,
            service_name,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            stop_service(&cli.server, app_id, service_name, private_key).await?;
        }
        Commands::AddToWhitelist { address } => {
            let private_key = require_private_key(&cli.private_key)?;
            add_to_whitelist(&cli.server, address, private_key).await?;
        }
        Commands::RemoveFromWhitelist { address } => {
            let private_key = require_private_key(&cli.private_key)?;
            remove_from_whitelist(&cli.server, address, private_key).await?;
        }
        Commands::ListWhitelist => {
            let private_key = require_private_key(&cli.private_key)?;
            list_whitelist(&cli.server, private_key).await?;
        }
        Commands::DockerLogin {
            registry,
            username,
            password,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            // Check environment variable if password is empty
            let password = if password.is_empty() {
                std::env::var("DOCKER_PASSWORD").unwrap_or_default()
            } else {
                password
            };
            docker_login(&cli.server, registry, username, password, private_key).await?;
        }
        Commands::DockerLogout { registry } => {
            let private_key = require_private_key(&cli.private_key)?;
            docker_logout(&cli.server, registry, private_key).await?;
        }
        Commands::PruneImages { all } => {
            let private_key = require_private_key(&cli.private_key)?;
            prune_images(&cli.server, all, private_key).await?;
        }
        Commands::GetTappInfo => {
            get_tapp_info(&cli.server).await?;
        }
        Commands::GetServiceStatus { log_lines } => {
            get_service_status(&cli.server, log_lines).await?;
        }
        Commands::GetServiceLogs {
            file_name,
            lines,
            download_full,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            get_service_logs(&cli.server, file_name, lines, download_full, private_key).await?;
        }
        Commands::WithdrawBalance {
            app_id,
            rpc_url,
            chain_id,
            recipient,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            withdraw_balance(
                &cli.server,
                app_id,
                rpc_url,
                chain_id,
                recipient,
                private_key,
            )
            .await?;
        }
        Commands::SignMessage {
            private_key,
            message,
        } => {
            sign_message(private_key, message)?;
        }
        Commands::VerifySignature {
            public_key,
            message,
            signature,
        } => {
            verify_signature(public_key, message, signature)?;
        }
        Commands::RegisterOnchain {
            app_id,
            rpc_url,
            contract,
            stake_wei,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            register_onchain(&cli.server, app_id, rpc_url, contract, stake_wei, private_key).await?;
        }
        Commands::UpdateOnchain {
            app_id,
            rpc_url,
            contract,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            update_onchain(&cli.server, app_id, rpc_url, contract, private_key).await?;
        }
        Commands::AddNodeOnchain {
            app_id,
            rpc_url,
            contract,
            stake_wei,
            signer_address,
            tee_url,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            add_node_onchain(&cli.server, app_id, rpc_url, contract, stake_wei, private_key, signer_address, tee_url).await?;
        }
        Commands::RemoveNodeOnchain {
            app_id,
            rpc_url,
            contract,
            signer_address,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            remove_node_onchain(&cli.server, app_id, rpc_url, contract, private_key, signer_address).await?;
        }
        Commands::UpdateNodeOnchain {
            app_id,
            rpc_url,
            contract,
            old_signer,
            new_signer,
            tee_url,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            update_node_onchain(&cli.server, app_id, rpc_url, contract, private_key, old_signer, new_signer, tee_url).await?;
        }

        Commands::Withdraw {
            rpc_url,
            contract,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            withdraw_onchain(rpc_url, contract, private_key).await?;
        }
        Commands::AuthorizeInvalidatorOnchain {
            app_id,
            rpc_url,
            contract,
            invalidator,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            authorize_invalidator_onchain(app_id, rpc_url, contract, invalidator, private_key).await?;
        }
        Commands::RevokeInvalidatorOnchain {
            app_id,
            rpc_url,
            contract,
            invalidator,
        } => {
            let private_key = require_private_key(&cli.private_key)?;
            revoke_invalidator_onchain(app_id, rpc_url, contract, invalidator, private_key).await?;
        }
    }

    Ok(())
}

fn require_private_key(key: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    key.clone().ok_or_else(|| {
        "Private key required. Use --private-key or set TAPP_PRIVATE_KEY environment variable"
            .into()
    })
}

/// Recursively collect all files under a directory into MountFile entries.
/// `dir` is the directory to walk, `base_dir` is the root of the mount source
/// (so relative paths are computed from base_dir's parent), and `source_prefix`
/// is the original source path string from the compose file (e.g. `./nginx/ssl`).
fn collect_dir_files(
    dir: &std::path::Path,
    base_dir: &std::path::Path,
    source_prefix: &str,
    files: &mut Vec<MountFile>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let rel = path
                .strip_prefix(base_dir)
                .map_err(|e| format!("strip_prefix error: {}", e))?;
            let file_source_path =
                format!("{}/{}", source_prefix.trim_end_matches('/'), rel.to_string_lossy());
            let content = std::fs::read(&path)
                .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
            println!("    ✓ Found: {}", file_source_path);
            files.push(MountFile {
                source_path: file_source_path,
                content,
                mode: "0644".to_string(),
            });
        } else if path.is_dir() {
            collect_dir_files(&path, base_dir, source_prefix, files)?;
        }
    }
    Ok(())
}

/// Extract local volume mounts from docker-compose.yml content
fn extract_volume_mounts(
    compose_file: &PathBuf,
    compose_content: &str,
) -> Result<Vec<MountFile>, Box<dyn std::error::Error>> {
    use serde_yaml::Value;

    let mut mount_files = Vec::new();

    // Parse YAML
    let yaml: Value = serde_yaml::from_str(compose_content)
        .map_err(|e| format!("Failed to parse compose file: {}", e))?;

    // Get compose file's parent directory
    let compose_dir = compose_file
        .parent()
        .ok_or("Cannot determine compose file directory")?;

    // Navigate to services
    let services = yaml
        .get("services")
        .and_then(|v| v.as_mapping())
        .ok_or("No services found in compose file")?;

    println!("Scanning for local files to upload...");

    // Iterate through each service
    for (service_name, service_config) in services {
        let service_name_str = service_name.as_str().unwrap_or("unknown");

        // Get volumes array
        if let Some(volumes) = service_config.get("volumes").and_then(|v| v.as_sequence()) {
            for volume in volumes {
                // Volume can be a string like "./config.toml:/app/config.toml" or "./config.toml:/app/config.toml:ro"
                if let Some(volume_str) = volume.as_str() {
                    // Parse volume string
                    let parts: Vec<&str> = volume_str.split(':').collect();
                    if parts.is_empty() {
                        continue;
                    }

                    let source_path = parts[0].trim();

                    // Only process relative local paths starting with ./
                    // ../ paths are not supported: on the server each app is isolated under its
                    // own directory (/var/lib/tapp/apps/<app_id>/). A ../ source path would
                    // resolve outside that boundary, which the server rejects for security
                    // reasons. Copy the file into the compose directory and use a ./ path instead.
                    if source_path.starts_with("../") {
                        println!(
                            "  ✗ Unsupported: {} — ../ paths are not allowed. \
                            Copy the file into the compose directory and use a ./ path.",
                            source_path
                        );
                        continue;
                    }
                    if !source_path.starts_with("./") {
                        continue;
                    }

                    // Build absolute path
                    let local_file = compose_dir.join(source_path);

                    // Check if path exists as file or directory
                    if local_file.exists() && local_file.is_file() {
                        println!("  ✓ Found: {} -> {}", source_path, local_file.display());

                        // Read file content
                        let content = std::fs::read(&local_file).map_err(|e| {
                            format!("Failed to read {}: {}", local_file.display(), e)
                        })?;

                        mount_files.push(MountFile {
                            source_path: source_path.to_string(),
                            content,
                            mode: "0644".to_string(),
                        });
                    } else if local_file.exists() && local_file.is_dir() {
                        println!("  ✓ Dir:   {} -> {}", source_path, local_file.display());
                        collect_dir_files(&local_file, &local_file, source_path, &mut mount_files)?;
                    } else {
                        println!(
                            "  ⊘ Skipped: {} (not found at {})",
                            source_path,
                            local_file.display()
                        );
                    }
                }
            }
        }
    }

    if mount_files.is_empty() {
        println!("  ⚠️  No local files found to upload");
    } else {
        println!("Files to upload: {}", mount_files.len());
    }
    println!();

    Ok(mount_files)
}

async fn start_app(
    server: &str,
    compose_file: PathBuf,
    app_id: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    // Read compose file
    let compose_content = std::fs::read_to_string(&compose_file)?;

    // Auto-extract volume mounts from compose file
    let mount_files = extract_volume_mounts(&compose_file, &compose_content)?;

    // Create authenticated request with signature
    let mut request = Request::new(StartAppRequest {
        compose_content,
        app_id: app_id.clone(),
        mount_files,
    });

    // Add signature metadata
    add_signature_metadata(&mut request, &private_key, "StartApp")?;

    let response = client.start_app(request).await?;
    let result = response.into_inner();

    println!("✓ Application start requested");
    println!("  App ID: {}", app_id);
    println!("  Task ID: {}", result.task_id);
    println!("  Message: {}", result.message);

    // Show command to check progress with server parameter if not using default
    let check_command = if server == "http://127.0.0.1:50051" {
        format!("tapp-cli get-task-status --task-id {}", result.task_id)
    } else {
        format!(
            "tapp-cli --server {} get-task-status --task-id {}",
            server, result.task_id
        )
    };
    println!("\nUse '{}' to check progress", check_command);

    Ok(())
}

async fn stop_app(
    server: &str,
    app_id: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(StopAppRequest {
        app_id: app_id.clone(),
    });

    add_signature_metadata(&mut request, &private_key, "StopApp")?;

    let response = client.stop_app(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Application stopped successfully");
        println!("  App ID: {}", app_id);
        println!("  Message: {}", result.message);
    } else {
        eprintln!("✗ Failed to stop application");
        eprintln!("  Message: {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

/// Convert TaskStatus enum to human-readable string
fn task_status_to_string(status: i32) -> String {
    match status {
        0 => "Pending".to_string(),
        1 => "Running".to_string(),
        2 => "Completed".to_string(),
        3 => "Failed".to_string(),
        _ => format!("Unknown ({})", status),
    }
}

/// Format Unix timestamp to human-readable datetime
fn format_timestamp(timestamp: i64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap_or_else(|| Utc::now());
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

async fn get_task_status(server: &str, task_id: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetTaskStatusRequest {
        task_id: task_id.clone(),
    });

    let response = client.get_task_status(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    let status_str = task_status_to_string(result.status);
    let status_icon = match result.status {
        0 => "⏳", // Pending
        1 => "🔄", // Running
        2 => "✓",  // Completed
        3 => "✗",  // Failed
        _ => "?",
    };

    println!("Task Status");
    println!("  Task ID: {}", task_id);
    println!("  Status: {} {}", status_icon, status_str);
    println!("  Created: {}", format_timestamp(result.created_at));
    println!("  Updated: {}", format_timestamp(result.updated_at));

    if let Some(task_result) = result.result {
        if !task_result.app_id.is_empty() {
            println!("  App ID: {}", task_result.app_id);
            println!("  Deployer: {}", task_result.deployer);
        }
        if !task_result.error.is_empty() {
            println!("  Error: {}", task_result.error);
        }
    }

    Ok(())
}

async fn get_app_info(server: &str, app_id: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetAppInfoRequest {
        app_id: app_id.clone(),
    });

    let response = client.get_app_info(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("Application Information");
    println!("  App ID: {}", result.app_id);
    println!("  Owner: {}", result.owner);
    println!("  Compose Hash: {}", result.compose_hash);
    println!("  Volumes Hash: {:?}", result.volumes_hash);
    println!("  Image Hash: {:?}", result.image_hash);

    Ok(())
}

async fn verify_app_cmd(
    server: &str,
    app_id: &str,
    rpc_url: Option<String>,
    contract: Option<String>,
    as_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Direct mode: no --contract → verify the single --server node without chain reconciliation.
    if contract.is_none() {
        let d = tapp_service::verify::verify_node_direct(server, app_id, as_endpoint).await?;
        let quote_ok = d.ear_status == "affirming";
        println!("Verifying app: {}  (direct mode — no on-chain reconciliation)", app_id);
        println!("  server      : {}", d.server);
        println!("  signer      : {}  (attested in report_data)", d.signer);
        println!("  AS          : ear.status={} tcb_status={} advisories={}", d.ear_status, d.tcb_status, d.advisories);
        if !d.compose_hash.is_empty() {
            println!("  compose     : {}", d.compose_hash);
        }
        if !d.images.is_empty() {
            println!("  images      : {:?}", d.images);
        }
        if !d.note.is_empty() {
            println!("  note        : {}", d.note);
        }
        println!("\nQuote {}", if quote_ok { "trusted ✅".to_string() } else { format!("untrusted ⚠️ ({}/{})", d.ear_status, d.tcb_status) });
        println!("(direct mode shows what the node attests; register on-chain + use --contract to reconcile)");
        return Ok(());
    }

    // Chain mode.
    let rpc_url = rpc_url.ok_or("chain mode requires --rpc-url (or omit --contract for direct mode)")?;
    let contract = contract.unwrap();
    let verdict = tapp_service::verify::verify_app(&rpc_url, &contract, app_id, as_endpoint).await?;

    let yn = |b: bool| if b { "✓" } else { "✗" };
    println!("Verifying app: {}  ({} node(s))", verdict.app_id, verdict.nodes.len());
    let mut all_ok = true;
    for n in &verdict.nodes {
        let reconciled = n.reconciled();
        let quote_ok = n.ear_status == "affirming";
        all_ok &= reconciled;
        println!("\n  node {}", n.signer);
        println!("    teeUrl     : {}", n.tee_url);
        if !n.reachable {
            println!("    ✗ unreachable / {}", n.note);
            all_ok = false;
            continue;
        }
        println!(
            "    AS         : ear.status={} tcb_status={} advisories={}",
            n.ear_status, n.tcb_status, n.advisories
        );
        println!(
            "    reconcile  : signer{} compose{} volumes{} image{}",
            yn(n.signer_ok), yn(n.compose_ok), yn(n.volumes_ok), yn(n.image_ok)
        );
        if !n.note.is_empty() {
            println!("    note       : {}", n.note);
        }
        println!(
            "    => reconcile {} ; quote {}",
            if reconciled { "PASS" } else { "FAIL" },
            if quote_ok { "trusted".to_string() } else { format!("untrusted ({}/{})", n.ear_status, n.tcb_status) }
        );
    }
    println!("\nResult: reconciliation {}", if all_ok { "ALL PASS ✅" } else { "has failures ❌" });
    Ok(())
}

async fn list_apps(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let response = client.list_apps(Request::new(ListAppsRequest {})).await?;
    let result = response.into_inner();

    if result.apps.is_empty() {
        println!("No apps on this server.");
        return Ok(());
    }

    println!("Apps ({}):", result.apps.len());
    for a in &result.apps {
        let compose = if a.compose_hash.len() > 16 {
            format!("{}…", &a.compose_hash[..16])
        } else {
            a.compose_hash.clone()
        };
        println!(
            "  {}\n    owner={}  compose={}  images={}",
            a.app_id, a.owner, compose, a.image_count
        );
    }

    Ok(())
}

async fn get_app_logs(
    server: &str,
    app_id: String,
    lines: i32,
    service: Option<String>,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(GetAppLogsRequest {
        app_id,
        lines,
        service_name: service.unwrap_or_default(),
    });

    add_signature_metadata(&mut request, &private_key, "GetAppLogs")?;

    let response = client.get_app_logs(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("{}", result.content);

    Ok(())
}

async fn get_app_container_status(
    server: &str,
    app_id: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(GetAppContainerStatusRequest {
        app_id: app_id.clone(),
    });

    add_signature_metadata(&mut request, &private_key, "GetAppContainerStatus")?;

    let response = client.get_app_container_status(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("Container Status for: {}", app_id);
    println!("  Running: {}", result.running);
    println!("  Container Count: {}", result.container_count);

    for container in result.containers {
        println!("\n  Container: {}", container.name);
        println!("    State: {}", container.state);
        if !container.health.is_empty() {
            println!("    Health: {}", container.health);
        }
        if !container.ports.is_empty() {
            println!("    Ports: {}", container.ports.join(", "));
        }
    }

    Ok(())
}

async fn get_evidence(server: &str, app_id: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetEvidenceRequest { app_id });

    let response = client.get_evidence(request).await?;
    let result = response.into_inner();

    println!("✓ Evidence generated successfully");
    println!("  TEE Type: {}", result.tee_type);
    println!("  Evidence (hex): {}", hex::encode(&result.evidence));
    println!("  Evidence (base64): {}", base64::encode(&result.evidence));

    Ok(())
}

async fn get_app_key(
    server: &str,
    app_id: String,
    key_type: String,
    x25519: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetAppKeyRequest {
        app_id: app_id.clone(),
        key_type: key_type.clone(),
        additional_data: vec![],
        kbs_resource_uri: String::new(),
        x25519,
    });

    let response = client.get_app_key(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("✓ Application key retrieved");
    println!("  App ID: {}", app_id);
    println!("  Key Type: {}", key_type);
    println!("  Key Source: {}", result.key_source);
    println!("  Public Key (hex): 0x{}", hex::encode(&result.public_key));

    if key_type == "ethereum" && !result.eth_address.is_empty() {
        println!("  Ethereum Address: 0x{}", hex::encode(&result.eth_address));
    }

    if x25519 && !result.x25519_public_key.is_empty() {
        println!(
            "  X25519 Public Key: 0x{}",
            hex::encode(&result.x25519_public_key)
        );
    }

    Ok(())
}

async fn get_app_secret_key(
    server: &str,
    app_id: String,
    json_output: bool,
    x25519: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetAppSecretKeyRequest {
        app_id: app_id.clone(),
        key_type: "ethereum".to_string(),
        x25519,
    });

    let response = match client.get_app_secret_key(request).await {
        Ok(resp) => resp,
        Err(e) if e.code() == tonic::Code::PermissionDenied => {
            eprintln!("✗ Permission denied: {}", e.message());
            eprintln!("\nGetAppSecretKey can ONLY be called from localhost!");
            eprintln!("Private keys will NEVER be sent over the network.");
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    };

    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    if json_output {
        let output = serde_json::json!({
            "private_key": format!("0x{}", hex::encode(&result.private_key)),
            "public_key": format!("0x{}", hex::encode(&result.public_key)),
            "evm_address": if !result.eth_address.is_empty() {
                format!("0x{}", hex::encode(&result.eth_address))
            } else {
                String::new()
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("⚠️  SECRET KEY (KEEP SECURE!)");
        println!("  App ID: {}", app_id);
        println!("  Private Key: 0x{}", hex::encode(&result.private_key));
        println!("  Public Key: 0x{}", hex::encode(&result.public_key));
        if !result.eth_address.is_empty() {
            println!("  Ethereum Address: 0x{}", hex::encode(&result.eth_address));
        }
    }

    Ok(())
}

async fn get_secret_resource(
    server: &str,
    app_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetSecretResourceRequest {
        app_id: app_id.clone(),
    });

    let response = match client.get_secret_resource(request).await {
        Ok(resp) => resp,
        Err(e) if e.code() == tonic::Code::PermissionDenied => {
            eprintln!("✗ Permission denied: {}", e.message());
            eprintln!("\nGetSecretResource can ONLY be called from localhost!");
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    };

    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("✓ Secret resource retrieved");
    println!("  App ID: {}", app_id);
    println!("  Secret (hex): 0x{}", hex::encode(&result.secret));

    Ok(())
}

async fn start_service(
    server: &str,
    app_id: String,
    service_name: String,
    pull: bool,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(StartServiceRequest {
        app_id: app_id.clone(),
        service_name: service_name.clone(),
        pull_image: pull,
    });

    add_signature_metadata(&mut request, &private_key, "StartService")?;

    let response = client.start_service(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("✓ Service start requested");
    println!("  App ID: {}", app_id);
    println!("  Service: {}", service_name);
    println!("  Task ID: {}", result.task_id);

    // Show command to check progress with server parameter if not using default
    let check_command = if server == "http://127.0.0.1:50051" {
        format!("tapp-cli get-task-status --task-id {}", result.task_id)
    } else {
        format!(
            "tapp-cli --server {} get-task-status --task-id {}",
            server, result.task_id
        )
    };
    println!("\nUse '{}' to check progress", check_command);

    Ok(())
}

async fn stop_service(
    server: &str,
    app_id: String,
    service_name: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(StopServiceRequest {
        app_id: app_id.clone(),
        service_name: service_name.clone(),
    });

    add_signature_metadata(&mut request, &private_key, "StopService")?;

    let response = client.stop_service(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Service stopped");
        println!("  App ID: {}", app_id);
        println!("  Service: {}", service_name);
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

async fn add_to_whitelist(
    server: &str,
    address: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(AddToWhitelistRequest {
        evm_address: address.clone(),
    });

    add_signature_metadata(&mut request, &private_key, "AddToWhitelist")?;

    let response = client.add_to_whitelist(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Address added to whitelist");
        println!("  Address: {}", address);
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

async fn remove_from_whitelist(
    server: &str,
    address: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(RemoveFromWhitelistRequest {
        evm_address: address.clone(),
    });

    add_signature_metadata(&mut request, &private_key, "RemoveFromWhitelist")?;

    let response = client.remove_from_whitelist(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Address removed from whitelist");
        println!("  Address: {}", address);
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

async fn list_whitelist(
    server: &str,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(ListWhitelistRequest {});

    add_signature_metadata(&mut request, &private_key, "ListWhitelist")?;

    let response = client.list_whitelist(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("Whitelisted Addresses:");
    if result.addresses.is_empty() {
        println!("  (none)");
    } else {
        for addr in result.addresses {
            println!("  {}", addr);
        }
    }

    Ok(())
}

async fn docker_login(
    server: &str,
    registry: Option<String>,
    username: String,
    password: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(DockerLoginRequest {
        registry: registry.unwrap_or_default(),
        username,
        password,
    });

    add_signature_metadata(&mut request, &private_key, "DockerLogin")?;

    let response = client.docker_login(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Docker login successful");
        println!("  Registry: {}", result.registry);
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

async fn docker_logout(
    server: &str,
    registry: Option<String>,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(DockerLogoutRequest {
        registry: registry.unwrap_or_default(),
    });

    add_signature_metadata(&mut request, &private_key, "DockerLogout")?;

    let response = client.docker_logout(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Docker logout successful");
        println!("  Registry: {}", result.registry);
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

async fn prune_images(
    server: &str,
    all: bool,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    // Use longer timeout for prune operation (5 minutes)
    let endpoint = tonic::transport::Endpoint::from_shared(server.to_string())?
        .timeout(Duration::from_secs(300));

    let mut client = TappServiceClient::connect(endpoint).await?;

    let mut request = Request::new(PruneImagesRequest { all });

    add_signature_metadata(&mut request, &private_key, "PruneImages")?;

    println!("Pruning Docker images... (this may take a while)");

    let response = client.prune_images(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Docker images pruned");
        println!("  Images Deleted: {}", result.images_deleted);
        println!(
            "  Space Reclaimed: {} MB",
            result.space_reclaimed / 1024 / 1024
        );
        if !result.deleted_images.is_empty() {
            println!("  Deleted:");
            for img in result.deleted_images {
                println!("    - {}", img);
            }
        }
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

async fn get_tapp_info(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetTappInfoRequest {});

    let response = client.get_tapp_info(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("TAPP Service Information");
    println!("  Version: {}", result.version);

    if let Some(config) = result.config {
        if let Some(server_config) = config.server {
            println!("\nServer:");
            println!("  Bind Address: {}", server_config.bind_address);
            println!("  Permission Enabled: {}", server_config.permission_enabled);
            if !server_config.owner_address.is_empty() {
                println!("  Owner Address: {}", server_config.owner_address);
            }
        }

        if let Some(boot_config) = config.boot {
            println!("\nBoot:");
            println!("  AA Config Path: {}", boot_config.aa_config_path);
        }
    }

    Ok(())
}

async fn get_service_status(
    server: &str,
    log_lines: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetServiceStatusRequest { log_lines });

    let response = client.get_service_status(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    println!("Service Status");
    println!("  Unit: {}", result.unit_name);
    println!("  State: {}", result.active_state);
    println!("  Sub State: {}", result.sub_state);
    println!("  PID: {}", result.pid);
    println!("  Version: {}", result.version);

    if !result.recent_logs.is_empty() {
        println!("\nRecent Logs:");
        for log in result.recent_logs {
            println!("  {}", log);
        }
    }

    Ok(())
}

async fn get_service_logs(
    server: &str,
    file_name: Option<String>,
    lines: i32,
    download_full: bool,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(GetServiceLogsRequest {
        file_name: file_name.unwrap_or_default(),
        lines,
        download_full,
    });

    add_signature_metadata(&mut request, &private_key, "GetServiceLogs")?;

    let response = client.get_service_logs(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    if !result.available_files.is_empty() {
        println!("Available Log Files:");
        for file in result.available_files {
            println!("  {} ({} bytes)", file.file_name, file.size_bytes);
        }
    } else {
        println!("{}", result.content);
    }

    Ok(())
}

async fn withdraw_balance(
    server: &str,
    app_id: String,
    rpc_url: String,
    chain_id: u64,
    recipient: Option<String>,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let mut request = Request::new(WithdrawBalanceRequest {
        app_id: app_id.clone(),
        rpc_url,
        chain_id,
        recipient: recipient.unwrap_or_default(),
    });

    add_signature_metadata(&mut request, &private_key, "WithdrawBalance")?;

    let response = client.withdraw_balance(request).await?;
    let result = response.into_inner();

    if result.success {
        println!("✓ Balance withdrawn successfully");
        println!("  App ID: {}", app_id);
        println!("  Transaction Hash: {}", result.transaction_hash);
        println!("  From: {}", result.from_address);
        println!("  To: {}", result.to_address);
        println!("  Amount: {} Wei", result.amount);
        println!("  Gas Used: {}", result.gas_used);
    } else {
        eprintln!("✗ {}", result.message);
        std::process::exit(1);
    }

    Ok(())
}

fn sign_message(
    private_key_hex: String,
    message: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let private_key_hex = private_key_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if private_key_hex.len() != 64 {
        eprintln!(
            "✗ Private key must be 32 bytes (64 hex characters), got {}",
            private_key_hex.len()
        );
        std::process::exit(1);
    }

    let private_key = hex::decode(private_key_hex)?;
    let message_bytes = message.as_bytes();

    let signature = tapp_service::app_key::sign_message(&private_key, message_bytes)?;

    println!("✓ Message signed");
    println!("  Message: {}", message);
    println!("  Signature (hex): 0x{}", hex::encode(&signature));
    println!("  Signature (base64): {}", base64::encode(&signature));

    Ok(())
}

fn verify_signature(
    public_key_hex: String,
    message: String,
    signature_hex: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_hex = public_key_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let signature_hex = signature_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if public_key_hex.len() != 128 {
        eprintln!(
            "✗ Public key must be 64 bytes (128 hex characters), got {}",
            public_key_hex.len()
        );
        std::process::exit(1);
    }

    let public_key = hex::decode(public_key_hex)?;
    let signature = hex::decode(signature_hex)?;
    let message_bytes = message.as_bytes();

    let is_valid = tapp_service::app_key::verify_signature(&public_key, message_bytes, &signature)?;

    if is_valid {
        println!("✓ Signature is VALID");
    } else {
        println!("✗ Signature is INVALID");
        std::process::exit(1);
    }

    Ok(())
}

// ─── On-chain command handlers ────────────────────────────────────────────────

async fn fetch_signer_address(
    server: &str,
    app_id: &str,
) -> Result<ethers::types::Address, Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;
    let key_resp = client
        .get_app_key(Request::new(GetAppKeyRequest {
            app_id: app_id.to_owned(),
            key_type: "ethereum".to_string(),
            additional_data: vec![],
            kbs_resource_uri: String::new(),
            x25519: false,
        }))
        .await?
        .into_inner();

    if !key_resp.success {
        return Err(format!("GetAppKey failed: {}", key_resp.message).into());
    }
    if key_resp.eth_address.len() != 20 {
        return Err(format!("Unexpected eth_address length: {}", key_resp.eth_address.len()).into());
    }
    Ok(ethers::types::Address::from_slice(&key_resp.eth_address))
}

async fn fetch_app_hashes(
    server: &str,
    app_id: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>), Box<dyn std::error::Error>> {
    use tapp_service::onchain;
    let mut client = TappServiceClient::connect(server.to_string()).await?;
    let info_resp = client
        .get_app_info(Request::new(GetAppInfoRequest {
            app_id: app_id.to_owned(),
        }))
        .await?
        .into_inner();

    if !info_resp.success {
        return Err(format!("GetAppInfo failed: {}", info_resp.message).into());
    }

    let compose_hash = onchain::hex_to_bytes(&info_resp.compose_hash)?;
    let volumes_hash = onchain::combine_map_hashes(&info_resp.volumes_hash);
    let image_hashes = onchain::map_to_bytes_array(&info_resp.image_hash);
    Ok((compose_hash, volumes_hash, image_hashes))
}

/// Decide the per-node override to store on-chain: compare the node's own
/// (compose, volumes) against the app-level defaults read from chain and return empty
/// for whichever matches (so the node inherits the default and follows updateApp).
async fn node_override_hashes(
    rpc_url: &str,
    contract: &str,
    app_id: &str,
    node_compose: Vec<u8>,
    node_volumes: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let (app_compose, app_volumes) =
        tapp_service::onchain::get_app_default_hashes(rpc_url, contract, app_id).await?;
    let compose = if node_compose == app_compose { Vec::new() } else { node_compose };
    let volumes = if node_volumes == app_volumes { Vec::new() } else { node_volumes };
    Ok((compose, volumes))
}

async fn register_onchain(
    server: &str,
    app_id: String,
    rpc_url: String,
    contract: String,
    stake_wei: u128,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use ethers::types::U256;
    use tapp_service::onchain::OnchainParams;

    let (compose_hash, volumes_hash, image_hashes) = fetch_app_hashes(server, &app_id).await?;
    let signer_address = fetch_signer_address(server, &app_id).await?;

    let params = OnchainParams { rpc_url, contract, private_key };
    // compose/volumes become the app-level shared defaults; the first node inherits them.
    let tx = tapp_service::onchain::register_app(
        &params,
        &app_id,
        compose_hash,
        volumes_hash,
        image_hashes,
        signer_address,
        server, // the server URL is recorded on-chain as the node's evidence URL
        U256::from(stake_wei),
    )
    .await?;

    println!("✓ App registered on-chain");
    println!("  App ID: {}", app_id);
    println!("  Signer Address: 0x{}", hex::encode(signer_address));
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

async fn update_onchain(
    server: &str,
    app_id: String,
    rpc_url: String,
    contract: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use tapp_service::onchain::OnchainParams;

    // updates the app-level shared defaults (compose/volumes/images); per-node
    // overrides are updated via update-node-onchain.
    let (compose_hash, volumes_hash, image_hashes) = fetch_app_hashes(server, &app_id).await?;

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = tapp_service::onchain::update_app(&params, &app_id, compose_hash, volumes_hash, image_hashes).await?;

    println!("✓ App updated on-chain");
    println!("  App ID: {}", app_id);
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

async fn add_node_onchain(
    server: &str,
    app_id: String,
    rpc_url: String,
    contract: String,
    stake_wei: u128,
    private_key: String,
    signer_arg: Option<String>,
    tee_url_arg: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ethers::types::{Address, U256};
    use std::str::FromStr;
    use tapp_service::onchain::OnchainParams;

    let (signer, tee_url) = if let Some(addr) = signer_arg {
        let parsed = Address::from_str(addr.trim_start_matches("0x"))
            .map_err(|_| format!("Invalid signer address: {}", addr))?;
        (parsed, tee_url_arg.unwrap_or_else(|| server.to_string()))
    } else {
        let fetched = fetch_signer_address(server, &app_id).await?;
        (fetched, tee_url_arg.unwrap_or_else(|| server.to_string()))
    };

    // This node's own compose/volumes (fetched from the node being added). Store a
    // per-node override only when it differs from the app-level default; otherwise
    // pass empty so the node inherits the default (and follows future updateApp).
    let (node_compose, node_volumes, _image_hashes) = fetch_app_hashes(server, &app_id).await?;
    let (compose_hash, volumes_hash) =
        node_override_hashes(&rpc_url, &contract, &app_id, node_compose, node_volumes).await?;

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = tapp_service::onchain::add_node(
        &params, &app_id, signer, &tee_url, compose_hash, volumes_hash, U256::from(stake_wei),
    )
    .await?;

    println!("✓ Node added on-chain");
    println!("  App ID: {}", app_id);
    println!("  Signer Address: 0x{:x}", signer);
    println!("  TEE URL: {}", tee_url);
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

async fn remove_node_onchain(
    server: &str,
    app_id: String,
    rpc_url: String,
    contract: String,
    private_key: String,
    signer_address: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tapp_service::onchain::OnchainParams;

    let signer = if let Some(addr) = signer_address {
        addr.trim_start_matches("0x").parse::<ethers::types::Address>()?
    } else {
        fetch_signer_address(server, &app_id).await?
    };

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = tapp_service::onchain::remove_node(&params, &app_id, signer).await?;

    println!("✓ Node removal initiated on-chain");
    println!("  App ID: {}", app_id);
    println!("  Signer Address: 0x{}", hex::encode(signer));
    println!("  Tx Hash: 0x{:x}", tx);
    println!("  (stake locked; run withdraw-node-stake after lock period)");

    Ok(())
}

async fn update_node_onchain(
    server: &str,
    app_id: String,
    rpc_url: String,
    contract: String,
    private_key: String,
    old_signer_arg: Option<String>,
    new_signer_arg: Option<String>,
    tee_url_arg: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use ethers::types::Address;
    use std::str::FromStr;
    use tapp_service::onchain::OnchainParams;

    let old_signer_addr = if let Some(addr) = old_signer_arg {
        Address::from_str(addr.trim_start_matches("0x"))
            .map_err(|_| format!("Invalid old signer address: {}", addr))?
    } else {
        fetch_signer_address(server, &app_id).await?
    };
    let (new_signer, tee_url) = if let Some(addr) = new_signer_arg {
        let parsed = Address::from_str(addr.trim_start_matches("0x"))
            .map_err(|_| format!("Invalid new signer address: {}", addr))?;
        (parsed, tee_url_arg.unwrap_or_else(|| server.to_string()))
    } else {
        let fetched = fetch_signer_address(server, &app_id).await?;
        (fetched, tee_url_arg.unwrap_or_else(|| server.to_string()))
    };

    // refresh this node's compose/volumes from its server; store as a per-node override
    // only when it differs from the app-level default (else empty = inherit).
    let (node_compose, node_volumes, _image_hashes) = fetch_app_hashes(server, &app_id).await?;
    let (compose_hash, volumes_hash) =
        node_override_hashes(&rpc_url, &contract, &app_id, node_compose, node_volumes).await?;

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = tapp_service::onchain::update_node(
        &params, &app_id, old_signer_addr, new_signer, tee_url.clone(), compose_hash, volumes_hash,
    )
    .await?;

    println!("✓ Node updated on-chain");
    println!("  App ID: {}", app_id);
    println!("  Old Signer: 0x{:x}", old_signer_addr);
    println!("  New Signer: 0x{:x}", new_signer);
    println!("  TEE URL: {}", tee_url);
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

async fn withdraw_onchain(
    rpc_url: String,
    contract: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use tapp_service::onchain::{self, OnchainParams};

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = onchain::withdraw(&params).await?;

    println!("✓ Stake withdrawn");
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

async fn authorize_invalidator_onchain(
    app_id: String,
    rpc_url: String,
    contract: String,
    invalidator: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use ethers::types::Address;
    use std::str::FromStr;
    use tapp_service::onchain::{self, OnchainParams};

    let invalidator_addr = Address::from_str(invalidator.trim_start_matches("0x"))
        .map_err(|_| format!("Invalid invalidator address: {}", invalidator))?;

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = onchain::authorize_invalidator(&params, &app_id, invalidator_addr).await?;

    println!("✓ Invalidator authorized");
    println!("  App ID: {}", app_id);
    println!("  Invalidator: 0x{:x}", invalidator_addr);
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

async fn revoke_invalidator_onchain(
    app_id: String,
    rpc_url: String,
    contract: String,
    invalidator: String,
    private_key: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use ethers::types::Address;
    use std::str::FromStr;
    use tapp_service::onchain::{self, OnchainParams};

    let invalidator_addr = Address::from_str(invalidator.trim_start_matches("0x"))
        .map_err(|_| format!("Invalid invalidator address: {}", invalidator))?;

    let params = OnchainParams { rpc_url, contract, private_key };
    let tx = onchain::revoke_invalidator(&params, &app_id, invalidator_addr).await?;

    println!("✓ Invalidator revoked");
    println!("  App ID: {}", app_id);
    println!("  Invalidator: 0x{:x}", invalidator_addr);
    println!("  Tx Hash: 0x{:x}", tx);

    Ok(())
}

fn add_signature_metadata<T>(
    request: &mut Request<T>,
    private_key_hex: &str,
    method_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
    use sha3::{Digest, Keccak256};

    let private_key_hex = private_key_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if private_key_hex.len() != 64 {
        eprintln!(
            "✗ Private key must be 32 bytes (64 hex characters), got {}",
            private_key_hex.len()
        );
        std::process::exit(1);
    }

    let private_key = hex::decode(private_key_hex)?;
    let timestamp = chrono::Utc::now().timestamp();

    // Build message: "MethodName:timestamp" (same as Python script)
    let message = format!("{}:{}", method_name, timestamp);

    // Build Ethereum signed message hash (EIP-191) - same as Python's encode_defunct
    // Format: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let message_hash: [u8; 32] = hasher.finalize().into();

    // Sign the message hash with recovery ID (same as Python's sign_message)
    let signing_key =
        SigningKey::from_slice(&private_key).map_err(|e| format!("Invalid private key: {}", e))?;

    // Sign the prehashed message and try both recovery IDs to find the correct one
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&message_hash)
        .map_err(|e| format!("Failed to sign message: {}", e))?;

    // Convert to bytes: r (32 bytes) || s (32 bytes) || v (1 byte)
    // Ethereum format: 65 bytes total
    let mut sig_bytes = signature.to_bytes().to_vec();

    // Append recovery ID as v (27 or 28 for legacy format)
    // Ethereum uses v = recovery_id + 27
    // RecoveryId::to_byte() returns 0 or 1
    let v = recovery_id.to_byte() + 27;
    sig_bytes.push(v);

    let signature_hex = hex::encode(&sig_bytes);

    request
        .metadata_mut()
        .insert("x-signature", MetadataValue::try_from(signature_hex)?);
    request.metadata_mut().insert(
        "x-timestamp",
        MetadataValue::try_from(timestamp.to_string())?,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_file(dir: &std::path::Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn make_compose(volumes: &[&str]) -> String {
        let volume_lines: String = volumes
            .iter()
            .map(|v| format!("      - {}\n", v))
            .collect();
        format!(
            "services:\n  app:\n    image: test\n    volumes:\n{}",
            volume_lines
        )
    }

    #[test]
    fn test_extract_dot_slash_paths() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "config.yaml", "key: value");

        let compose_path = tmp.path().join("docker-compose.yaml");
        let content = make_compose(&["./config.yaml:/etc/config.yaml"]);

        let mounts = extract_volume_mounts(&compose_path, &content).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].source_path, "./config.yaml");
    }

    #[test]
    fn test_extract_dot_dot_paths() {
        let tmp = TempDir::new().unwrap();
        let compose_dir = tmp.path().join("deploy");
        fs::create_dir_all(&compose_dir).unwrap();
        let compose_path = compose_dir.join("docker-compose.yaml");
        let content = make_compose(&["../sibling/config.yaml:/etc/config.yaml"]);

        // ../ paths are not allowed and should be skipped
        let mounts = extract_volume_mounts(&compose_path, &content).unwrap();
        assert!(mounts.is_empty(), "../ paths should be rejected");
    }

    #[test]
    fn test_skip_named_volumes_and_absolute_paths() {
        let tmp = TempDir::new().unwrap();
        let compose_path = tmp.path().join("docker-compose.yaml");
        let content = make_compose(&[
            "myvolume:/data",
            "/absolute/path:/etc/file",
        ]);

        let mounts = extract_volume_mounts(&compose_path, &content).unwrap();
        assert!(mounts.is_empty(), "named volumes and absolute paths must be skipped");
    }
}
