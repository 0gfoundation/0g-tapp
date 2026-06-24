// Shared modules re-exported from tapp-common (no TEE/Docker deps)
pub use tapp_common::app_key;
pub use tapp_common::onchain;
pub use tapp_common::error;
pub use tapp_common::verify;
pub use tapp_common::proto;
pub use tapp_common::as_proto;

// Server-only modules
pub mod auth_layer;
pub mod balance_withdrawal;
pub mod kms_client;
pub mod boot;
pub mod config;
pub mod measurement_service;
pub mod nonce_manager;
pub mod permission;
pub mod service_monitor;
pub mod signature_auth;
pub mod task_manager;
pub mod utils;

pub use boot::BootService;
pub use config::TappConfig;
pub use tapp_common::error::{TappError, TappResult};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
pub use task_manager::TaskStatus;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};


// // Re-export common types
pub use proto::{
    tapp_service_client::TappServiceClient,
    tapp_service_server::{TappService, TappServiceServer},
    *,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

pub struct TappServiceImpl {
    pub config: TappConfig,
    pub boot_service: Arc<BootService>,
    pub app_key_service: app_key::AppKeyService,
    pub kms_client: Option<kms_client::KmsClient>,
    pub nonce_manager: nonce_manager::NonceManager,
    pub logs_service: service_monitor::logs::LogsService,
    pub permission_manager: Option<Arc<permission::PermissionManager>>,
    pub measurement_service: Arc<measurement_service::MeasurementService>,
}

impl TappServiceImpl {
    /// Check if an IP address is allowed for local access
    /// Allows:
    /// - Localhost (127.0.0.1, ::1)
    /// - Docker bridge networks (172.16.0.0/12)
    /// - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    fn is_allowed_local_access(ip: IpAddr) -> bool {
        use std::net::IpAddr;

        match ip {
            IpAddr::V4(ipv4) => {
                // Localhost: 127.0.0.1
                if ipv4.is_loopback() {
                    return true;
                }

                // Private networks (includes Docker networks)
                // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                if ipv4.is_private() {
                    return true;
                }

                false
            }
            IpAddr::V6(ipv6) => {
                // Localhost: ::1
                ipv6.is_loopback()
            }
        }
    }

    /// Determine the source type for logging
    /// Get source type description for logging
    fn get_source_type(ip: IpAddr) -> &'static str {
        use std::net::IpAddr;

        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() {
                    "localhost"
                } else if Self::is_docker_bridge_network(ipv4) {
                    "docker-bridge"
                } else if Self::is_docker_custom_network(ipv4) {
                    "docker-custom"
                } else if ipv4.is_private() {
                    "private-network"
                } else {
                    "public-network"
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() {
                    "localhost-ipv6"
                } else {
                    "ipv6-network"
                }
            }
        }
    }

    /// Check if IP is from Docker default bridge network (172.17.0.0/16)
    fn is_docker_bridge_network(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 172 && octets[1] == 17
    }

    /// Check if IP is from Docker custom networks (172.18-31.0.0/16)
    fn is_docker_custom_network(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 172 && (18..=31).contains(&octets[1])
    }

    pub async fn new(
        config: TappConfig,
        permission_manager: Option<Arc<permission::PermissionManager>>,
        measurement_service: Arc<measurement_service::MeasurementService>,
    ) -> TappResult<Self> {
        info!("Initializing TAPP service components");

        // Initialize TaskManager
        let task_manager = Arc::new(task_manager::TaskManager::new());

        // Initialize BootService with measurement_service and task_manager
        let boot_service =
            Arc::new(BootService::new(measurement_service.clone(), task_manager).await?);

        // Initialize AppKeyService (always in-memory, independent of KBS)
        let app_key_service = app_key::AppKeyService::new();

        // Initialize NonceManager for replay attack prevention
        let nonce_manager = nonce_manager::NonceManager::new();

        // Initialize LogsService
        let logs_service =
            service_monitor::logs::LogsService::new(config.logging.file_path.clone());

        // Initialize KMS client from KBS config (used for GetSecretResource)
        let kms_client = config.kbs.as_ref().map(|kbs| {
            info!(nodes = kbs.node_urls.len(), "Initializing KMS client from KBS config");
            kms_client::KmsClient::new(kbs.node_urls.clone(), &kbs.retry)
        });

        info!("All TAPP service components initialized successfully");

        Ok(Self {
            boot_service,
            app_key_service,
            kms_client,
            nonce_manager,
            logs_service,
            permission_manager,
            measurement_service,
            config,
        })
    }
}

#[tonic::async_trait]
impl TappService for TappServiceImpl {
    /// Get attestation evidence from TEE platform
    async fn get_evidence(
        &self,
        request: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        info!("Calling GetEvidence");
        debug!("Request: {:?}", request);
        let req = request.into_inner();
        // Use the app signer (TEE-derived ethereum address) as report_data so the
        // attestation binds to the on-chain registered signer.
        let key_pair = self
            .app_key_service
            .get_app_key(&req.app_id, "ethereum", false)
            .await?;
        let evidence = self
            .boot_service
            .get_evidence(req, &key_pair.eth_address)
            .await?;
        Ok(Response::new(evidence))
    }

    async fn start_app(
        &self,
        request: Request<StartAppRequest>,
    ) -> Result<Response<StartAppResponse>, Status> {
        // Signature validation is handled by AuthLayer
        // Get signer address before consuming request
        info!("Calling StartApp");
        debug!("Request: {:?}", request);
        let signer = auth_layer::get_signer_address(&request);
        let req_inner = request.into_inner();
        // let app_id = req_inner.app_id.clone();

        // Get deployer address (signer EVM address)
        // If no signer (auth disabled), use a default placeholder
        let deployer = signer
            .clone()
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

        // Start the app with deployer address
        let response = self
            .boot_service
            .clone()
            .start_app(req_inner, deployer.clone())
            .await?;

        // Record ownership if permission management is enabled
        // if let Some(pm) = &self.permission_manager {
        //     if let Some(signer_addr) = signer {
        //         pm.record_app_start(app_id.clone(), signer_addr.clone())
        //             .await;

        //         info!(
        //             app_id = %app_id,
        //             owner = %signer_addr,
        //             deployer = %deployer,
        //             event = "APP_OWNERSHIP_RECORDED",
        //             "App ownership recorded"
        //         );
        //     }
        // }

        Ok(Response::new(response))
    }

    async fn stop_app(
        &self,
        request: Request<StopAppRequest>,
    ) -> Result<Response<StopAppResponse>, Status> {
        // Get signer address before consuming request
        info!("Calling StopApp");
        debug!("Request: {:?}", request);
        let signer = auth_layer::get_signer_address(&request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();

        // Check ownership if permission management is enabled
        if let Some(pm) = &self.permission_manager {
            if let Some(signer_addr) = signer {
                // Check if user can manage this app
                if !pm.can_manage_app(&app_id, &signer_addr).await {
                    error!(
                        app_id = %app_id,
                        requester = %signer_addr,
                        event = "APP_STOP_AUTHORIZED",
                        "You don't have permission to stop app {}. Only the app owner or tapp owner can stop it.",
                        app_id
                    );
                    return Err(Status::permission_denied(format!(
                        "You don't have permission to stop app {}. Only the app owner or tapp owner can stop it.",
                        app_id
                    )));
                }

                info!(
                    app_id = %app_id,
                    requester = %signer_addr,
                    event = "APP_STOP_AUTHORIZED",
                    "User authorized to stop app"
                );
            }
        }

        // Stop the app
        self.boot_service.stop_app(&app_id).await?;

        // Mark app as stopped in ownership tracking
        if let Some(pm) = &self.permission_manager {
            pm.mark_app_stopped(&app_id).await;

            info!(
                app_id = %app_id,
                event = "APP_OWNERSHIP_UPDATED",
                "App marked as stopped"
            );
        }

        Ok(Response::new(StopAppResponse {
            success: true,
            message: format!("Application {} stopped successfully", app_id),
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn get_task_status(
        &self,
        request: Request<GetTaskStatusRequest>,
    ) -> Result<Response<GetTaskStatusResponse>, Status> {
        info!("Calling GetTaskStatus");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        match self.boot_service.get_task_status(&req.task_id).await {
            Some(task) => {
                let is_success = matches!(task.status, TaskStatus::Completed(_));

                Ok(Response::new(GetTaskStatusResponse {
                    success: is_success,
                    message: match &task.status {
                        TaskStatus::Pending => "Task is pending".to_string(),
                        TaskStatus::Running => "Task is running".to_string(),
                        TaskStatus::Completed(_) => "Task completed successfully".to_string(),
                        TaskStatus::Failed(err) => format!("Task failed: {}", err),
                    },
                    task_id: task.id.clone(),
                    status: task.to_proto_status() as i32,
                    result: task.to_proto_result(),
                    created_at: task.created_at,
                    updated_at: task.updated_at,
                }))
            }
            None => Ok(Response::new(GetTaskStatusResponse {
                success: false,
                message: format!("Task not found: {}", req.task_id),
                task_id: req.task_id,
                status: 0,
                result: None,
                created_at: 0,
                updated_at: 0,
            })),
        }
    }

    // DEPRECATED: Removed since we no longer store measurement history in memory
    // Only current running app info is stored in memory (app_info)
    // Complete measurement history is in TEE measurements
    async fn list_app_measurements(
        &self,
        _request: Request<ListAppMeasurementsRequest>,
    ) -> Result<Response<ListAppMeasurementsResponse>, Status> {
        Err(Status::unimplemented(
            "list_app_measurements is deprecated - use get_app_info for current running apps",
        ))
    }

    async fn get_app_key(
        &self,
        request: Request<GetAppKeyRequest>,
    ) -> Result<Response<GetAppKeyResponse>, Status> {
        info!("Calling GetAppKey");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        // Default to "ethereum" if key_type is not specified
        // TODO: Remove
        // let key_type = if req.key_type.is_empty() {
        //     "ethereum"
        // } else {
        //     &req.key_type
        // };

        let response = self.app_key_service.get_public_key(&req.app_id).await?;
        Ok(Response::new(GetAppKeyResponse {
            success: true,
            message: format!("Public key for app {}", req.app_id),
            eth_address: response.0,
            public_key: response.1,
            x25519_public_key: response.2.unwrap_or_default(),
            key_source: "in-memory".to_string(),
        }))
    }

    async fn get_app_secret_key(
        &self,
        request: Request<GetAppSecretKeyRequest>,
    ) -> Result<Response<GetAppSecretKeyResponse>, Status> {
        info!("Calling GetAppSecretKey");
        debug!("Request: {:?}", request);
        // SECURITY: Extract remote address BEFORE consuming request
        let remote_addr = request.remote_addr();

        // SECURITY: Validate that the request is from localhost or Docker network
        let (is_allowed, source_type) = if let Some(addr) = remote_addr {
            let ip = addr.ip();
            let allowed = Self::is_allowed_local_access(ip);
            let source = Self::get_source_type(ip);
            (allowed, source)
        } else {
            // No remote address (e.g., Unix socket) - allow
            (true, "unix-socket")
        };

        if !is_allowed {
            tracing::error!(
                remote_addr = ?remote_addr,
                event = "SECRET_KEY_ACCESS_DENIED",
                reason = "not in allowed network range",
                "Rejected GetAppSecretKey request from non-allowed address"
            );

            return Err(Status::permission_denied(
                "GetAppSecretKey can only be called from localhost or same-host Docker containers",
            ));
        }

        // Get signer address from signature (handled by AuthLayer)
        // let signer = auth_layer::get_signer_address(&request);
        let req = request.into_inner();
        let mut key_type = "ethereum".to_string();
        if !req.key_type.is_empty() {
            key_type = req.key_type;
        }

        // // SECURITY: Check app ownership
        // if let Some(pm) = &self.permission_manager {
        //     if let Some(signer_addr) = &signer {
        //         if !pm.can_manage_app(&req.app_id, signer_addr).await {
        //             tracing::error!(
        //                 app_id = %req.app_id,
        //                 signer = %signer_addr,
        //                 remote_addr = ?remote_addr,
        //                 event = "SECRET_KEY_ACCESS_DENIED",
        //                 reason = "not app owner or tapp owner",
        //                 "Permission denied: only app owner or tapp owner can access secret key"
        //             );

        //             return Err(Status::permission_denied(
        //                 "Only the app owner or tapp owner can access the app's secret key",
        //             ));
        //         }
        //     }
        // }

        // Get the app info to get compose_hash, volumes_hash, deployer
        let app_info = self
            .boot_service
            .get_app_info(&req.app_id)
            .await?
            .ok_or_else(|| {
                tracing::warn!(
                    app_id = %req.app_id,
                    event = "SECRET_KEY_ACCESS_DENIED",
                    reason = "app not found",
                    "App not found"
                );
                Status::not_found(format!("App {} not found", req.app_id))
            })?;

        // SECURITY: Log all private key access attempts
        tracing::warn!(
            app_id = %req.app_id,
            remote_addr = ?remote_addr,
            source_type = source_type,
            event = "SECRET_KEY_ACCESS",
            timestamp = %chrono::Utc::now(),
            "Private key access attempt from allowed source"
        );

        // Create base measurement for this operation
        let base_measurement = boot::AppMeasurement {
            app_id: req.app_id.clone(),
            operation: measurement_service::OPERATION_NAME_GET_APP_SECRET_KEY.to_string(),
            result: String::new(),
            error: None,
            compose_hash: app_info.compose_content.hash.clone(),
            volumes_hash: app_info.mount_files.hash.clone(),
            image_hash: app_info.compose_content.image_hash.clone(),
            deployer: app_info.owner.clone(),
            timestamp: utils::current_timestamp(),
        };

        // Try to get the key
        let result = async {
            // Get public key and address for response
            let key_response = self
                .app_key_service
                .get_app_key(&req.app_id, &key_type, req.x25519)
                .await?;

            // Get private key
            // let private_key = self.app_key_service.get_private_key(&req.app_id).await?;

            Ok::<_, crate::error::TappError>(key_response)
        }
        .await;

        // Mark measurement as success or failure
        let final_measurement = match &result {
            Ok(_) => base_measurement.with_success(),
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Extend measurement (both success and failure)
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_GET_APP_SECRET_KEY,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement for get_app_secret_key: {}", e);
        }

        // Handle result
        match result {
            Ok(key_response) => {
                // SECURITY: Log successful retrieval
                tracing::warn!(
                    app_id = %req.app_id,
                    // signer = ?signer,
                    remote_addr = ?remote_addr,
                    source_type = source_type,
                    // accessor = signer.as_deref().unwrap_or("unknown"),
                    event = "SECRET_KEY_RETRIEVED",
                    timestamp = %chrono::Utc::now(),
                    "Private key successfully retrieved"
                );

                Ok(Response::new(GetAppSecretKeyResponse {
                    success: true,
                    message: format!("Private key for app {}", req.app_id),
                    private_key: key_response.private_key,
                    public_key: key_response.public_key,
                    eth_address: key_response.eth_address,
                    x25519_public_key: key_response.x25519_public_key.unwrap_or_default(),
                }))
            }
            Err(e) => {
                tracing::error!(
                    app_id = %req.app_id,
                    // signer = ?signer,
                    remote_addr = ?remote_addr,
                    event = "SECRET_KEY_RETRIEVAL_FAILED",
                    error = %e,
                    "Failed to retrieve private key"
                );
                Err(e.into())
            }
        }
    }

    async fn get_app_info(
        &self,
        request: Request<GetAppInfoRequest>,
    ) -> Result<Response<GetAppInfoResponse>, Status> {
        info!("Calling GetAppInfo");
        debug!("Request: {:?}", request);
        let req = request.into_inner();
        let app_id = req.app_id;

        let app_info = self.boot_service.get_app_info(&app_id).await?;

        let app_info = app_info.ok_or(TappError::InvalidParameter {
            field: "app_id".to_string(),
            reason: format!("App {} not found", app_id),
        })?;

        Ok(Response::new(GetAppInfoResponse {
            success: true,
            message: format!("App info for {}", app_id),
            app_id,
            owner: app_info.owner,
            compose_hash: app_info.compose_content.hash,
            volumes_hash: app_info.mount_files.hash.into_iter().collect(),
            image_hash: app_info.compose_content.image_hash.into_iter().collect(),
            compose_content: app_info.compose_content.content,
            // volumes_content: app_info.mount_files.content,
        }))
    }

    async fn list_apps(
        &self,
        _request: Request<ListAppsRequest>,
    ) -> Result<Response<ListAppsResponse>, Status> {
        info!("Calling ListApps");
        let apps = self
            .boot_service
            .list_apps()
            .await
            .into_iter()
            .map(|(app_id, owner, compose_hash, image_count)| AppSummary {
                app_id,
                owner,
                compose_hash,
                image_count: image_count as u32,
            })
            .collect();

        Ok(Response::new(ListAppsResponse {
            success: true,
            apps,
        }))
    }

    async fn get_tapp_info(
        &self,
        _request: Request<GetTappInfoRequest>,
    ) -> Result<Response<GetTappInfoResponse>, Status> {
        info!("Calling GetTappInfo");

        // Build logging config
        let logging_config = LoggingConfigInfo {
            level: self.config.logging.level.clone(),
            format: self.config.logging.format.clone(),
            file_path: self
                .config
                .logging
                .file_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
        };

        // Build server config
        let server_config = ServerConfigInfo {
            bind_address: self.config.server.bind_address.clone(),
            max_connections: self.config.server.max_connections as i32,
            request_timeout_seconds: self.config.server.request_timeout_seconds as i32,
            tls_enabled: self.config.server.tls_enabled,
            tls_cert_configured: self.config.server.tls_cert_path.is_some(),
            permission_enabled: self
                .config
                .server
                .permission
                .as_ref()
                .map(|p| p.enabled)
                .unwrap_or(false),
            owner_address: self
                .config
                .server
                .permission
                .as_ref()
                .map(|p| p.owner_address.clone())
                .unwrap_or_default(),
        };

        // Build boot config
        let boot_config = BootConfigInfo {
            aa_config_path: self
                .config
                .boot
                .aa_config_path
                .as_ref()
                .cloned()
                .unwrap_or_default(),
        };

        // Build KBS config if available
        let kbs_enabled = self.config.kbs.is_some();
        let kbs_config = self.config.kbs.as_ref().map(|kbs| {
            let retry_config = RetryConfigInfo {
                max_retries: kbs.retry.max_retries as i32,
                initial_delay_ms: kbs.retry.initial_delay_ms as i32,
                max_delay_ms: kbs.retry.max_delay_ms as i32,
            };

            KbsConfigInfo {
                node_urls: kbs.node_urls.clone(),
                timeout_seconds: kbs.timeout_seconds as i32,
                cert_configured: kbs.cert_path.is_some(),
                retry: Some(retry_config),
            }
        });

        // Build complete config info
        let config_info = TappConfigInfo {
            logging: Some(logging_config),
            server: Some(server_config),
            boot: Some(boot_config),
            kbs: kbs_config,
            kbs_enabled,
        };

        Ok(Response::new(GetTappInfoResponse {
            success: true,
            message: "TAPP configuration retrieved successfully".to_string(),
            config: Some(config_info),
            version: VERSION.to_string(),
        }))
    }

    async fn get_service_status(
        &self,
        request: Request<GetServiceStatusRequest>,
    ) -> Result<Response<GetServiceStatusResponse>, Status> {
        info!("Calling GetServiceStatus");
        debug!("Request: {:?}", request);
        use tokio::process::Command;

        let req = request.into_inner();
        let log_lines = if req.log_lines > 0 { req.log_lines } else { 50 };

        info!(log_lines = log_lines, "Processing GetServiceStatus request");

        // Determine the systemd unit name
        // Try to detect from environment or use default
        let unit_name =
            std::env::var("SYSTEMD_UNIT").unwrap_or_else(|_| "tapp-server.service".to_string());

        // Get service status using systemctl show
        let status_output = Command::new("systemctl")
            .args(&["show", &unit_name, "--no-pager"])
            .output()
            .await;

        let (active_state, sub_state, active_since_timestamp, pid) = match status_output {
            Ok(output) if output.status.success() => {
                let status_text = String::from_utf8_lossy(&output.stdout);
                let mut active_state = String::from("unknown");
                let mut sub_state = String::from("unknown");
                let mut active_since = 0i64;
                let mut main_pid = 0i32;

                for line in status_text.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        match key {
                            "ActiveState" => active_state = value.to_string(),
                            "SubState" => sub_state = value.to_string(),
                            "ActiveEnterTimestamp" => {
                                // Parse timestamp (e.g., "Mon 2024-01-06 10:30:15 UTC")
                                // For now, we'll try to get the unix timestamp
                                if let Ok(ts) = value.parse::<i64>() {
                                    active_since = ts;
                                }
                            }
                            "ActiveEnterTimestampMonotonic" => {
                                if active_since == 0 {
                                    if let Ok(ts) = value.parse::<i64>() {
                                        // Convert monotonic to unix timestamp (approximate)
                                        active_since = ts / 1_000_000; // microseconds to seconds
                                    }
                                }
                            }
                            "MainPID" => {
                                if let Ok(p) = value.parse::<i32>() {
                                    main_pid = p;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                (active_state, sub_state, active_since, main_pid)
            }
            Ok(output) => {
                let error_text = String::from_utf8_lossy(&output.stderr);
                info!(
                    unit_name = %unit_name,
                    error = %error_text,
                    "systemctl show command failed"
                );
                ("unknown".to_string(), "error".to_string(), 0, 0)
            }
            Err(e) => {
                info!(
                    unit_name = %unit_name,
                    error = %e,
                    "Failed to execute systemctl command"
                );
                ("unknown".to_string(), "not-available".to_string(), 0, 0)
            }
        };

        // Get recent logs using journalctl
        let logs_output = Command::new("journalctl")
            .args(&[
                "-u",
                &unit_name,
                "-n",
                &log_lines.to_string(),
                "--no-pager",
                "--output=short-iso",
            ])
            .output()
            .await;

        let (recent_logs, log_lines_returned) = match logs_output {
            Ok(output) if output.status.success() => {
                let logs_text = String::from_utf8_lossy(&output.stdout);
                let logs: Vec<String> = logs_text.lines().map(|s| s.to_string()).collect();
                let count = logs.len() as i32;
                (logs, count)
            }
            Ok(output) => {
                let error_text = String::from_utf8_lossy(&output.stderr);
                info!(
                    unit_name = %unit_name,
                    error = %error_text,
                    "journalctl command failed"
                );
                (
                    vec![format!("Failed to retrieve logs: {}", error_text.trim())],
                    0,
                )
            }
            Err(e) => {
                info!(
                    unit_name = %unit_name,
                    error = %e,
                    "Failed to execute journalctl command"
                );
                (vec![format!("journalctl command not available: {}", e)], 0)
            }
        };

        Ok(Response::new(GetServiceStatusResponse {
            success: true,
            message: format!("Service status for {}", unit_name),
            unit_name,
            active_state,
            sub_state,
            active_since_timestamp,
            pid,
            recent_logs,
            log_lines_returned,
            timestamp: crate::utils::current_timestamp(),
            version: VERSION.to_string(),
        }))
    }

    async fn get_service_logs(
        &self,
        request: Request<GetServiceLogsRequest>,
    ) -> Result<Response<GetServiceLogsResponse>, Status> {
        info!("Calling GetServiceLogs");
        debug!("Request: {:?}", request);
        let req = request.into_inner();
        let response = self.logs_service.get_logs(req).await?;
        Ok(Response::new(response))
    }

    async fn get_app_logs(
        &self,
        request: Request<GetAppLogsRequest>,
    ) -> Result<Response<GetAppLogsResponse>, Status> {
        info!("Calling GetAppLogs");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        let service_name = if req.service_name.is_empty() {
            None
        } else {
            Some(req.service_name.as_str())
        };

        let content = self
            .boot_service
            .get_app_logs(&req.app_id, req.lines, service_name)
            .await?;

        let total_lines = content.lines().count() as i32;

        Ok(Response::new(GetAppLogsResponse {
            success: true,
            message: format!("Retrieved {} lines from app {}", total_lines, req.app_id),
            content,
            total_lines,
        }))
    }

    // ============================================================================
    // Permission Management Methods
    // ============================================================================

    async fn add_to_whitelist(
        &self,
        request: Request<AddToWhitelistRequest>,
    ) -> Result<Response<AddToWhitelistResponse>, Status> {
        info!("Calling AddToWhitelist");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Add address to whitelist
        pm.add_to_whitelist(req.evm_address.clone())
            .await
            .map_err(|e| Status::internal(format!("Failed to add to whitelist: {}", e)))?;

        // Extend runtime measurement for this security-critical operation
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_ADD_TO_WHITELIST,
            "address": req.evm_address,
            "timestamp": utils::current_timestamp()
        })
        .to_string();

        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_ADD_TO_WHITELIST,
                &measurement_data,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to extend measurement: {}", e)))?;

        info!(
            address = %req.evm_address,
            event = "WHITELIST_ADDED",
            "Address added to whitelist and measurement extended"
        );

        Ok(Response::new(AddToWhitelistResponse {
            success: true,
            message: format!("Address {} added to whitelist", req.evm_address),
        }))
    }

    async fn remove_from_whitelist(
        &self,
        request: Request<RemoveFromWhitelistRequest>,
    ) -> Result<Response<RemoveFromWhitelistResponse>, Status> {
        info!("Calling RemoveFromWhitelist");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Remove address from whitelist
        pm.remove_from_whitelist(&req.evm_address)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove from whitelist: {}", e)))?;

        // Extend runtime measurement for this security-critical operation
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_REMOVE_FROM_WHITELIST,
            "address": req.evm_address,
            "timestamp": utils::current_timestamp()
        })
        .to_string();

        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_REMOVE_FROM_WHITELIST,
                &measurement_data,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to extend measurement: {}", e)))?;

        info!(
            address = %req.evm_address,
            event = "WHITELIST_REMOVED",
            "Address removed from whitelist and measurement extended"
        );

        Ok(Response::new(RemoveFromWhitelistResponse {
            success: true,
            message: format!("Address {} removed from whitelist", req.evm_address),
        }))
    }

    async fn list_whitelist(
        &self,
        _request: Request<ListWhitelistRequest>,
    ) -> Result<Response<ListWhitelistResponse>, Status> {
        info!("Calling ListWhitelist");
        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        let addresses = pm.list_whitelist().await;

        Ok(Response::new(ListWhitelistResponse {
            success: true,
            message: format!("Found {} whitelisted address(es)", addresses.len()),
            addresses,
        }))
    }

    async fn get_app_ownership(
        &self,
        request: Request<GetAppOwnershipRequest>,
    ) -> Result<Response<GetAppOwnershipResponse>, Status> {
        info!("Calling GetAppOwnership");
        debug!("Request: {:?}", request);
        // Get signer address before consuming request
        let signer = auth_layer::get_signer_address(&request)
            .ok_or_else(|| Status::unauthenticated("Signer address not found"))?;

        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Check if user can view this app's ownership
        // Owner can view all, others can only view if they can manage the app
        if !pm.can_manage_app(&req.app_id, &signer).await && signer != pm.get_tapp_owner_address() {
            return Err(Status::permission_denied(
                "You don't have permission to view this app's ownership",
            ));
        }

        let ownership = pm.get_app_ownership(&req.app_id).await;

        match ownership {
            Some(own) => Ok(Response::new(GetAppOwnershipResponse {
                success: true,
                message: format!("Ownership info for app {}", req.app_id),
                ownership: Some(AppOwnershipInfo {
                    app_id: own.app_id,
                    owner_address: own.owner_address,
                    started_at: own.started_at,
                    status: match own.status {
                        permission::AppStatus::Active => proto::AppStatus::Active.into(),
                        permission::AppStatus::Stopped => proto::AppStatus::Stopped.into(),
                    },
                    stopped_at: own.stopped_at.unwrap_or(0),
                }),
            })),
            None => Err(Status::not_found(format!("App {} not found", req.app_id))),
        }
    }

    async fn list_all_ownerships(
        &self,
        _request: Request<ListAllOwnershipsRequest>,
    ) -> Result<Response<ListAllOwnershipsResponse>, Status> {
        info!("Calling ListAllOwnerships");
        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        let ownerships_list = pm.list_all_ownerships().await;

        let ownerships: Vec<AppOwnershipInfo> = ownerships_list
            .into_iter()
            .map(|own| AppOwnershipInfo {
                app_id: own.app_id,
                owner_address: own.owner_address,
                started_at: own.started_at,
                status: match own.status {
                    permission::AppStatus::Active => proto::AppStatus::Active.into(),
                    permission::AppStatus::Stopped => proto::AppStatus::Stopped.into(),
                },
                stopped_at: own.stopped_at.unwrap_or(0),
            })
            .collect();

        Ok(Response::new(ListAllOwnershipsResponse {
            success: true,
            message: format!("Found {} app ownership(s)", ownerships.len()),
            ownerships,
        }))
    }

    async fn withdraw_balance(
        &self,
        request: Request<WithdrawBalanceRequest>,
    ) -> Result<Response<WithdrawBalanceResponse>, Status> {
        info!("Calling WithdrawBalance");
        debug!("Request: {:?}", request);
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let app_id = &req.app_id;

        // Get app private key
        let private_key = self
            .app_key_service
            .get_private_key(app_id)
            .await
            .map_err(|e| Status::not_found(format!("App key not found: {}", e)))?;

        // Determine recipient
        let recipient = if req.recipient.is_empty() {
            self.permission_manager
                .as_ref()
                .map(|pm| pm.get_tapp_owner_address().to_string())
                .ok_or_else(|| Status::internal("TAPP owner not configured"))?
        } else {
            req.recipient.clone()
        };

        // Execute withdrawal
        let result = balance_withdrawal::withdraw_balance(
            &private_key,
            &req.rpc_url,
            req.chain_id,
            &recipient,
        )
        .await
        .map_err(|e| Status::internal(format!("Withdrawal failed: {}", e)))?;

        // Record measurement
        let measurement = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_WITHDRAW_BALANCE,
            "app_id": app_id,
            "from_address": result.from_address,
            "to_address": result.to_address,
            "amount": result.amount,
            "transaction_hash": result.transaction_hash,
            "chain_id": req.chain_id,
            "signer": signer,
            "timestamp": chrono::Utc::now().timestamp(),
        });

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_WITHDRAW_BALANCE,
                &measurement.to_string(),
            )
            .await
        {
            tracing::warn!(error = ?e, "Failed to record withdrawal measurement");
        }

        tracing::info!(
            app_id = %app_id,
            tx_hash = %result.transaction_hash,
            amount = %result.amount,
            event = "WITHDRAW_BALANCE_SUCCESS",
            "Balance withdrawal successful"
        );

        Ok(Response::new(WithdrawBalanceResponse {
            success: true,
            message: "Withdrawal successful".to_string(),
            transaction_hash: result.transaction_hash,
            from_address: result.from_address,
            to_address: result.to_address,
            amount: result.amount,
            gas_used: result.gas_used,
            gas_price: result.gas_price.parse().unwrap_or(0),
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn docker_login(
        &self,
        request: Request<DockerLoginRequest>,
    ) -> Result<Response<DockerLoginResponse>, Status> {
        info!("Calling DockerLogin");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let registry = req.registry.clone();
        let username = req.username.clone();

        // Execute docker login
        self.boot_service
            .docker_login(&registry, &username, &req.password)
            .await?;

        // Determine actual registry for response
        let actual_registry = if registry.is_empty() {
            "docker.io".to_string()
        } else {
            registry
        };

        // Record measurement
        let measurement = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_DOCKER_LOGIN,
            "registry": actual_registry.clone(),
            "username": username.clone(),
            "signer": signer.clone(),
            "timestamp": chrono::Utc::now().timestamp(),
        });

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_DOCKER_LOGIN,
                &measurement.to_string(),
            )
            .await
        {
            tracing::warn!(error = ?e, "Failed to record docker login measurement");
        }

        tracing::info!(
            registry = %actual_registry,
            username = %username,
            signer = %signer.unwrap_or_default(),
            event = "DOCKER_LOGIN_SUCCESS",
            "Docker login successful"
        );

        Ok(Response::new(DockerLoginResponse {
            success: true,
            message: format!("Successfully logged into {}", actual_registry),
            registry: actual_registry,
            username,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn docker_logout(
        &self,
        request: Request<DockerLogoutRequest>,
    ) -> Result<Response<DockerLogoutResponse>, Status> {
        info!("Calling DockerLogout");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let registry = req.registry.clone();

        // Execute docker logout
        self.boot_service.docker_logout(&registry).await?;

        // Determine actual registry for response
        let actual_registry = if registry.is_empty() {
            "docker.io".to_string()
        } else {
            registry
        };

        // Record measurement
        let measurement = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_DOCKER_LOGOUT,
            "registry": actual_registry.clone(),
            "signer": signer.clone(),
            "timestamp": chrono::Utc::now().timestamp(),
        });

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_DOCKER_LOGOUT,
                &measurement.to_string(),
            )
            .await
        {
            tracing::warn!(error = ?e, "Failed to record docker logout measurement");
        }

        tracing::info!(
            registry = %actual_registry,
            signer = %signer.unwrap_or_default(),
            event = "DOCKER_LOGOUT_SUCCESS",
            "Docker logout successful"
        );

        Ok(Response::new(DockerLogoutResponse {
            success: true,
            message: format!("Successfully logged out from {}", actual_registry),
            registry: actual_registry,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn stop_service(
        &self,
        request: Request<StopServiceRequest>,
    ) -> Result<Response<StopServiceResponse>, Status> {
        // Get signer address before consuming request
        info!("Calling StopService");
        debug!("Request: {:?}", request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();
        let service_name = req_inner.service_name.clone();

        // Stop the service
        self.boot_service
            .stop_service(&app_id, &service_name)
            .await?;

        Ok(Response::new(StopServiceResponse {
            success: true,
            message: format!("Service {}.{} stopped successfully", app_id, service_name),
            app_id,
            service_name,
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn start_service(
        &self,
        request: Request<StartServiceRequest>,
    ) -> Result<Response<StartServiceResponse>, Status> {
        // Signature validation is handled by AuthLayer
        // Get signer address before consuming request
        info!("Calling StartService");
        debug!("Request: {:?}", request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();
        let service_name = req_inner.service_name.clone();
        let pull_image = req_inner.pull_image;

        // Start the service (returns task_id for async operation)
        let task_id = self
            .boot_service
            .clone()
            .start_service(app_id.clone(), service_name.clone(), pull_image)
            .await?;

        Ok(Response::new(StartServiceResponse {
            success: true,
            message: format!(
                "Task created successfully for starting service {}.{} Use task_id to check status.",
                app_id, service_name
            ),
            task_id,
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn prune_images(
        &self,
        request: Request<PruneImagesRequest>,
    ) -> Result<Response<PruneImagesResponse>, Status> {
        info!("Calling PruneImages");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let all = req.all;
        // Execute docker image prune
        let result = self.boot_service.prune_images(all).await?;

        tracing::info!(
            images_deleted = result.images_deleted,
            space_reclaimed = result.space_reclaimed,
            signer = %signer.unwrap_or_default(),
            event = "DOCKER_PRUNE_IMAGES_SUCCESS",
            "Docker image prune successful"
        );

        Ok(Response::new(PruneImagesResponse {
            success: true,
            message: format!(
                "Pruned {} images, reclaimed {} bytes",
                result.images_deleted, result.space_reclaimed
            ),
            images_deleted: result.images_deleted,
            space_reclaimed: result.space_reclaimed,
            deleted_images: result.deleted_images,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn get_app_container_status(
        &self,
        request: Request<GetAppContainerStatusRequest>,
    ) -> Result<Response<GetAppContainerStatusResponse>, Status> {
        info!("Calling GetAppContainerStatus");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let app_id = req.app_id.clone();

        let _ = self
            .boot_service
            .get_app_info(&app_id)
            .await?
            .ok_or_else(|| {
                tracing::warn!(
                    app_id = %app_id,
                    event = "SECRET_KEY_ACCESS_DENIED",
                    reason = "app not found",
                    "App not found"
                );
                Status::not_found(format!("App {} not found", app_id))
            })?;

        // Get container status (app may not exist, but we still return status)
        let app_status = self.boot_service.get_app_container_status(&app_id).await?;

        // Convert to proto response
        let containers: Vec<proto::ContainerStatus> = app_status
            .containers
            .into_iter()
            .map(|c| proto::ContainerStatus {
                name: c.name,
                state: c.state,
                health: c.health.unwrap_or_default(),
                ports: c.ports,
            })
            .collect();

        let container_count = app_status.container_count as i32;
        let running = app_status.running;
        let started_at = app_status.started_at.unwrap_or(0);

        tracing::info!(
            app_id = %app_id,
            container_count = container_count,
            running = running,
            containers_len = containers.len(),
            started_at = started_at,
            signer = %signer.unwrap_or_default(),
            event = "GET_APP_CONTAINER_STATUS_SUCCESS",
            "Get app container status successful"
        );

        let response = GetAppContainerStatusResponse {
            success: true,
            message: format!(
                "App {} has {} containers, running: {}",
                app_id, container_count, running
            ),
            app_id: app_id.clone(),
            running,
            container_count,
            containers,
            started_at,
            timestamp: chrono::Utc::now().timestamp(),
        };

        // Debug: log response fields
        tracing::debug!(
            app_id = %response.app_id,
            running = response.running,
            container_count = response.container_count,
            containers_count = response.containers.len(),
            started_at = response.started_at,
            "Response fields set"
        );

        Ok(Response::new(response))
    }

    async fn get_secret_resource(
        &self,
        request: Request<GetSecretResourceRequest>,
    ) -> Result<Response<GetSecretResourceResponse>, Status> {
        info!("Calling GetSecretResource");

        // SECURITY: local access only
        let remote_addr = request.remote_addr();
        let allowed = remote_addr
            .map(|a| Self::is_allowed_local_access(a.ip()))
            .unwrap_or(true); // Unix socket
        if !allowed {
            return Err(Status::permission_denied(
                "GetSecretResource can only be called from localhost or same-host Docker containers",
            ));
        }

        let req = request.into_inner();
        let app_id = &req.app_id;

        let kms = self.kms_client.as_ref().ok_or_else(|| {
            Status::failed_precondition("KMS not configured (set [kms] cluster_urls in config)")
        })?;

        // Get in-memory key pair: private key for signing + decryption, pubkey for KMS encryption target
        let private_key = self
            .app_key_service
            .get_private_key(app_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get app key: {}", e)))?;

        let (_, secp256k1_pubkey_64, _) = self
            .app_key_service
            .get_public_key(app_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get app public key: {}", e)))?;

        // ecies expects uncompressed secp256k1 pubkey: 0x04 || 64 bytes
        let pubkey_uncompressed = [&[0x04u8], secp256k1_pubkey_64.as_slice()].concat();
        let pubkey_hex = hex::encode(&pubkey_uncompressed);

        // Sign KMS request: EIP-191 personal_sign over "GetSecretResource:{timestamp}"
        // (KMS server verifies via ecrecover, so signature must be 65-byte r||s||v).
        let timestamp = chrono::Utc::now().timestamp();
        let message = signature_auth::build_sign_message("GetSecretResource", timestamp);
        let signature = app_key::sign_message_eip191(&private_key, message.as_bytes())
            .map_err(|e| Status::internal(format!("Failed to sign KMS request: {}", e)))?;
        let signature_hex = hex::encode(&signature);

        // Call KMS cluster → get ECIES-encrypted app key
        let encrypted = kms
            .get_encrypted_secret(app_id, timestamp, &pubkey_hex, &signature_hex)
            .await
            .map_err(|e| Status::unavailable(format!("KMS request failed: {}", e)))?;

        // Decrypt with our private key
        let secret = ecies::decrypt(&private_key, &encrypted)
            .map_err(|e| Status::internal(format!("Failed to decrypt KMS secret: {}", e)))?;

        info!(app_id = %app_id, "GetSecretResource succeeded");

        Ok(Response::new(GetSecretResourceResponse {
            success: true,
            message: format!("Secret resource retrieved for app {}", app_id),
            secret,
        }))
    }
}

/// Initialize tracing based on configuration
pub fn init_tracing(config: &config::LoggingConfig) -> TappResult<()> {
    use tracing_subscriber::{
        fmt::{self, format::FmtSpan},
        layer::SubscriberExt,
        util::SubscriberInitExt,
        EnvFilter, Layer,
    };

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.level))
        .map_err(|e| error::ConfigError::InvalidValue {
            field: "logging.level".to_string(),
            reason: format!("Invalid log level: {}", e),
        })?;

    let stdout_layer = match config.format.as_str() {
        "json" => fmt::layer()
            .json()
            .with_writer(std::io::stdout)
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        "pretty" => fmt::layer()
            .pretty()
            .with_writer(std::io::stdout)
            .with_ansi(true)
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        _ => {
            return Err(error::ConfigError::InvalidValue {
                field: "logging.format".to_string(),
                reason: format!("Unsupported log format: {}", config.format),
            }
            .into());
        }
    };

    if let Some(file_path) = &config.file_path {
        use tracing_appender::rolling::{RollingFileAppender, Rotation};

        let path = std::path::Path::new(file_path);

        let (directory, file_name_prefix) = if file_path.to_string_lossy().ends_with('/') {
            (path, "app")
        } else if path.extension().is_some() {
            let directory = path.parent().unwrap_or(std::path::Path::new("."));
            let file_name_prefix = path.file_stem().and_then(|n| n.to_str()).unwrap_or("app");
            (directory, file_name_prefix)
        } else {
            let directory = path.parent().unwrap_or(std::path::Path::new("."));
            let file_name_prefix = path.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            (directory, file_name_prefix)
        };

        std::fs::create_dir_all(directory).map_err(|e| error::ConfigError::InvalidValue {
            field: "logging.file_path".to_string(),
            reason: format!("Cannot create log directory: {}", e),
        })?;

        let file_appender = RollingFileAppender::new(Rotation::DAILY, directory, file_name_prefix);

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        std::mem::forget(_guard);

        let file_layer = match config.format.as_str() {
            "json" => fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE)
                .boxed(),
            "pretty" => fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE)
                .boxed(),
            _ => unreachable!(),
        };

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_app_id() {
        assert!(utils::validate_app_id("my-app"));
        assert!(utils::validate_app_id("app_123"));
        assert!(utils::validate_app_id("test-application-1"));

        assert!(!utils::validate_app_id("ab")); // too short
        assert!(!utils::validate_app_id("a".repeat(65).as_str())); // too long
        assert!(!utils::validate_app_id("app@123")); // invalid character
        assert!(!utils::validate_app_id("app space")); // contains space
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"hello world";
        let hash = utils::sha256_hex(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(utils::format_bytes(0), "0 B");
        assert_eq!(utils::format_bytes(1024), "1.00 KB");
        assert_eq!(utils::format_bytes(1536), "1.50 KB");
        assert_eq!(utils::format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_pad_to_length() {
        let data = b"hello";
        let padded = utils::pad_to_length(data, 10);
        assert_eq!(padded.len(), 10);
        assert_eq!(&padded[0..5], b"hello");
        assert_eq!(&padded[5..], &[0u8; 5]);
    }
}
