pub mod compose_lint;
pub mod compose_override;
pub mod manager;
pub mod measurement;
pub mod volume;

pub use manager::{AppStatus, ContainerStatus, DockerComposeManager, MountFile, PruneImagesResult};
pub use measurement::{AppMeasurement, ComposeMeasurement, HashAlgorithm};

/// Deferred fetch of an app's volume passphrase, built by the RPC layer (which
/// owns the KMS client) and awaited inside the start task (so a slow KMS round
/// trip delays the task, never the StartApp RPC). `None` = this node has no KMS
/// configured, and the app runs on a plain directory.
pub type VolumeKeyFut =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>>;

use crate::error::{DockerError, TappError, TappResult};
use crate::measurement_service::MeasurementService;
use crate::proto::{GetEvidenceRequest, GetEvidenceResponse, StartAppRequest, StartAppResponse};
use crate::task_manager::{Task, TaskManager, TaskSuccessResult};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

/// Put the hashed bytes into the evidence next to `quote` and `cc_eventlog`, so a
/// verifier receives everything it needs as one object and never has to be told
/// separately what `report_data` committed to.
///
/// The attester's output is JSON for every TEE we support, but if it ever isn't the
/// evidence is passed through untouched: losing the field degrades a verifier to the
/// old signer-only reading, whereas returning a mangled blob would break it outright.
fn attach_runtime_data(evidence: Vec<u8>, runtime_data: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let mut parsed: serde_json::Value = match serde_json::from_slice(&evidence) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "evidence is not JSON; runtime_data not attached");
            return evidence;
        }
    };
    let Some(obj) = parsed.as_object_mut() else {
        warn!("evidence is not a JSON object; runtime_data not attached");
        return evidence;
    };
    obj.insert(
        crate::report_data::EVIDENCE_FIELD.to_string(),
        serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(runtime_data),
        ),
    );
    match serde_json::to_vec(&parsed) {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "re-serialising evidence failed; returning original");
            evidence
        }
    }
}

#[derive(Clone)]
pub struct AppComposeContent {
    pub hash: String,
    pub content: String,
    pub image_hash: std::collections::BTreeMap<String, String>, // Map: service_name -> image
}

#[derive(Clone)]
pub struct AppMountFiles {
    pub hash: std::collections::BTreeMap<String, String>, // Map: file_name -> hash
    pub content: String,
}

#[derive(Clone)]
pub struct AppInfo {
    pub app_id: String,
    pub owner: String,
    pub compose_content: AppComposeContent,
    pub mount_files: AppMountFiles,
}

pub struct BootService {
    app_info: Mutex<HashMap<String, AppInfo>>,
    measurement_service: Arc<MeasurementService>,
    task_manager: Arc<TaskManager>,
}

impl BootService {
    /// Ensure attestation agent config file exists with default values
    pub fn ensure_aa_config(config_path: &str) -> TappResult<()> {
        let path = Path::new(config_path);

        // If file already exists, do nothing
        if path.exists() {
            return Ok(());
        }

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DockerError::ContainerOperationFailed {
                operation: "create_config_dir".to_string(),
                reason: format!("Failed to create config directory: {}", e),
            })?;
        }

        // Create default config file with enable_eventlog = true
        let default_config = r#"[eventlog_config]
enable_eventlog = true
"#;

        std::fs::write(path, default_config).map_err(|e| {
            DockerError::ContainerOperationFailed {
                operation: "write_config".to_string(),
                reason: format!("Failed to write default config: {}", e),
            }
        })?;

        info!(
            "Created default attestation-agent config at: {}",
            config_path
        );
        Ok(())
    }

    /// Create new Docker Compose service
    pub async fn new(
        measurement_service: Arc<MeasurementService>,
        task_manager: Arc<TaskManager>,
    ) -> TappResult<Self> {
        Ok(Self {
            app_info: Mutex::new(HashMap::new()),
            measurement_service,
            task_manager,
        })
    }

    /// Internal method to handle the actual app start logic
    async fn _start_app(
        &self,
        request: StartAppRequest,
        deployer: String,
        task_id: String,
        volume_key: Option<VolumeKeyFut>,
    ) {
        let app_id = request.app_id.clone();

        // Check if app already exists
        {
            let app_info_lock = self.app_info.lock().await;
            if let Some(existing_info) = app_info_lock.get(&app_id) {
                // If hash is not empty, app is still running
                if !existing_info.compose_content.hash.is_empty() {
                    let error_msg = format!("App {} is already running", app_id);
                    tracing::error!(app_id = %app_id, "App already running");
                    self.task_manager.mark_failed(&task_id, error_msg).await;
                    return;
                }
                // If hash is empty, app is stopped, check if same owner
                if existing_info.owner != deployer {
                    let error_msg = format!(
                        "App {} was deployed by different owner: {} (current: {})",
                        app_id, existing_info.owner, deployer
                    );
                    tracing::error!(
                        app_id = %app_id,
                        existing_owner = %existing_info.owner,
                        current_deployer = %deployer,
                        "Owner mismatch for stopped app"
                    );
                    self.task_manager.mark_failed(&task_id, error_msg).await;
                    return;
                }
                // Same owner restarting stopped app - OK to proceed
                info!(
                    app_id = %app_id,
                    owner = %deployer,
                    "Restarting stopped app with same owner"
                );
            }
        }

        // Convert proto MountFile to our MountFile structure (needed for both success and failure)
        let mount_files: Vec<MountFile> = request
            .mount_files
            .iter()
            .map(|mf| MountFile {
                source_path: mf.source_path.clone(),
                content: mf.content.clone(),
                mode: if mf.mode.is_empty() {
                    "0644".to_string()
                } else {
                    mf.mode.clone()
                },
            })
            .collect();

        // Measure-only: pull images and compute hashes, but don't start containers.
        // Result (compose/volumes/image hashes) is returned via the task result so
        // the CLI can register the app on-chain before actually starting it.
        if request.measure_only {
            let image_hash = match DockerComposeManager::pull_and_measure(
                &app_id,
                &request.compose_content,
                &mount_files,
            )
            .await
            {
                Ok(map) => map,
                Err(e) => {
                    self.task_manager
                        .mark_failed(&task_id, format!("Failed to pull/measure images: {}", e))
                        .await;
                    return;
                }
            };

            let measurement = match self
                .calculate_app_measurement(
                    &request,
                    &mount_files,
                    &app_id,
                    &deployer,
                    crate::measurement_service::OPERATION_NAME_START_APP,
                    image_hash.clone(),
                )
                .await
            {
                Ok((m, _, _)) => m,
                Err(e) => {
                    self.task_manager
                        .mark_failed(&task_id, format!("Failed to calculate measurement: {}", e))
                        .await;
                    return;
                }
            };

            // Note: no extend_measurement and no AppInfo registration here — the
            // app has not run; the follow-up real StartApp does both as usual.
            self.task_manager
                .mark_completed(
                    &task_id,
                    TaskSuccessResult {
                        app_id,
                        deployer,
                        compose_hash: measurement.compose_hash,
                        volumes_hash: measurement.volumes_hash,
                        image_hash,
                    },
                )
                .await;
            return;
        }

        // Encrypted data volume first, so `./data` is already the encrypted
        // mount when files are staged and containers start. Strict on failure:
        // starting the app on a plain directory instead would be a silent
        // downgrade the owner cannot see.
        match volume_key {
            Some(key_fut) => {
                let mounted = async {
                    let key = key_fut.await.map_err(|e| {
                        TappError::from(DockerError::ContainerOperationFailed {
                            operation: "fde_volume_key".to_string(),
                            reason: format!(
                                "KMS refused the volume key: {e} — the app's data volume \
                                 cannot be opened. Is this node registered on-chain for \
                                 the app (start-app --register-onchain)?"
                            ),
                        })
                    })?;
                    volume::ensure_mounted(&app_id, &key).await
                }
                .await;
                if let Err(e) = mounted {
                    tracing::error!(app_id = %app_id, error = %e, "Failed to mount encrypted volume");
                    self.task_manager.mark_failed(&task_id, format!("{e}")).await;
                    return;
                }
            }
            None => {
                warn!(
                    app_id = %app_id,
                    "No KMS configured on this node — app data is NOT encrypted at rest"
                );
            }
        }

        // Try to start the application
        let deploy_result = async {
            info!(
                task_id = %task_id,
                app_id = %app_id,
                mount_files_count = request.mount_files.len(),
                "Starting application with Docker Compose"
            );

            // Start the Docker Compose application with mount files
            // This returns the actual image hashes from running containers
            let image_hash = DockerComposeManager::deploy_compose(
                &app_id,
                &request.compose_content,
                &mount_files,
            )
            .await?;

            info!(
                task_id = %task_id,
                app_id = %app_id,
                "Application started successfully"
            );

            Ok::<_, crate::error::TappError>(image_hash)
        }
        .await;

        // Calculate measurement with actual image hashes (or empty map on failure)
        let (image_hash, measurement_result) = match &deploy_result {
            Ok(img_hash) => {
                // Success: use actual image hashes
                (
                    img_hash.clone(),
                    self.calculate_app_measurement(
                        &request,
                        &mount_files,
                        &app_id,
                        &deployer,
                        crate::measurement_service::OPERATION_NAME_START_APP,
                        img_hash.clone(),
                    )
                    .await,
                )
            }
            Err(_) => {
                // Failure: use empty image hash map
                let empty_map = std::collections::BTreeMap::new();
                (
                    empty_map.clone(),
                    self.calculate_app_measurement(
                        &request,
                        &mount_files,
                        &app_id,
                        &deployer,
                        crate::measurement_service::OPERATION_NAME_START_APP,
                        empty_map,
                    )
                    .await,
                )
            }
        };

        // Handle the measurement calculation result
        let (base_measurement, compose_content, volumes_content) = match measurement_result {
            Ok(result) => result,
            Err(e) => {
                // If measurement calculation fails, cleanup and mark task as failed
                if deploy_result.is_ok() {
                    // Cleanup containers if deployment succeeded but measurement failed
                    if let Err(cleanup_err) = DockerComposeManager::stop_compose(&app_id).await {
                        tracing::error!(
                            app_id = %app_id,
                            error = %cleanup_err,
                            "Failed to cleanup containers after measurement calculation failure"
                        );
                    }
                }
                self.task_manager
                    .mark_failed(&task_id, format!("Failed to calculate measurement: {}", e))
                    .await;
                return;
            }
        };

        // Save values from base_measurement before it's moved
        let compose_hash = base_measurement.compose_hash.clone();
        let volumes_hash = base_measurement.volumes_hash.clone();
        let image_hash_clone = image_hash.clone();

        // Mark measurement as success or failure based on deploy result
        let final_measurement = match &deploy_result {
            Ok(_) => base_measurement.with_success(),
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Extend runtime measurement (ONCE for both success/failure)
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        // info!("measurement_json: {}", measurement_json);

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                crate::measurement_service::OPERATION_NAME_START_APP,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement: {}", e);
        }

        // Handle result: store AppInfo on success, cleanup on failure
        match deploy_result {
            Ok(_) => {
                // Store AppInfo in memory (only on success)
                let app_info = AppInfo {
                    app_id: app_id.clone(),
                    owner: deployer.clone(),
                    compose_content: AppComposeContent {
                        hash: compose_hash,
                        content: compose_content,
                        image_hash: image_hash_clone,
                    },
                    mount_files: AppMountFiles {
                        hash: volumes_hash,
                        content: volumes_content,
                    },
                };

                self.app_info.lock().await.insert(app_id.clone(), app_info);

                // Mark task as completed
                self.task_manager
                    .mark_completed(
                        &task_id,
                        TaskSuccessResult { app_id, deployer, ..Default::default() },
                    )
                    .await;
            }
            Err(e) => {
                // Before cleanup, get container logs for debugging
                // This helps diagnose startup failures before containers are removed
                // First, try to identify failed services and only get their logs
                let failed_services = DockerComposeManager::get_failed_services(&app_id)
                    .await
                    .unwrap_or_default();

                let logs_result = if !failed_services.is_empty() {
                    // Get logs from failed services only
                    // Collect logs from each failed service
                    let mut all_logs = String::new();
                    let mut has_logs = false;

                    for service in &failed_services {
                        if let Ok(service_logs) =
                            DockerComposeManager::get_app_logs(&app_id, 0, Some(service)).await
                        {
                            if !service_logs.trim().is_empty() {
                                if has_logs {
                                    all_logs.push_str("\n\n");
                                }
                                all_logs.push_str(&format!(
                                    "=== Service: {} ===\n{}",
                                    service, service_logs
                                ));
                                has_logs = true;
                            }
                        }
                    }

                    if has_logs {
                        Ok(all_logs)
                    } else {
                        // Fallback: get all logs if failed to get specific service logs
                        DockerComposeManager::get_app_logs(&app_id, 0, None).await
                    }
                } else {
                    // No failed services identified, get all logs
                    DockerComposeManager::get_app_logs(&app_id, 0, None).await
                };
                if let Ok(logs) = &logs_result {
                    if !logs.trim().is_empty() {
                        tracing::error!(
                            app_id = %app_id,
                            logs = %logs,
                            "Container logs before cleanup"
                        );
                    }
                } else if let Err(log_err) = &logs_result {
                    tracing::warn!(
                        app_id = %app_id,
                        error = %log_err,
                        "Failed to get container logs before cleanup"
                    );
                }

                // Cleanup: stop and remove containers on failure
                // Note: Failed start already measured above
                tracing::error!(
                    app_id = %app_id,
                    error = %e,
                    "Failed to start application, cleanup containers"
                );

                // Include logs in error message if available
                // Limit log size to 1MB to avoid memory issues
                let error_msg = if let Ok(logs) = logs_result {
                    if !logs.trim().is_empty() {
                        // Truncate logs if too large (limit to 1MB)
                        const MAX_LOG_SIZE: usize = 1024 * 1024; // 1MB
                        let truncated_logs = if logs.len() > MAX_LOG_SIZE {
                            let truncated = format!(
                                "... (truncated, showing last {} bytes) ...\n{}",
                                MAX_LOG_SIZE,
                                &logs[logs.len() - MAX_LOG_SIZE..]
                            );
                            truncated
                        } else {
                            logs
                        };
                        format!(
                            "{}\n\nContainer logs (all services):\n{}",
                            e, truncated_logs
                        )
                    } else {
                        format!("{}", e)
                    }
                } else {
                    format!("{}", e)
                };

                if let Err(cleanup_err) = DockerComposeManager::stop_compose(&app_id).await {
                    tracing::error!(
                        app_id = %app_id,
                        error = %cleanup_err,
                        "Failed to cleanup containers after deployment failure"
                    );
                }

                // Mark task as failed with logs included
                self.task_manager.mark_failed(&task_id, error_msg).await;
            }
        }
    }

    /// Handle start app request (async - returns task ID immediately)
    /// This method should be called with Arc<Self> from the service implementation
    pub async fn start_app(
        self: std::sync::Arc<Self>,
        request: StartAppRequest,
        deployer: String, // EVM address from signature authentication
        volume_key: Option<VolumeKeyFut>,
    ) -> TappResult<StartAppResponse> {
        // Validate request
        self.validate_request(&request)?;

        // Create a new task
        let task = self.task_manager.create_task().await;
        let task_id = task.id.clone();

        info!(
            task_id = %task_id,
            app_id = %request.app_id,
            "Created task for starting application"
        );

        // Mark task as running
        self.task_manager.mark_running(&task_id).await;

        // Clone Arc for background task
        let service = self.clone();
        let task_id_clone = task_id.clone();

        // Spawn background task
        tokio::spawn(async move {
            service
                ._start_app(request, deployer, task_id_clone, volume_key)
                .await;
        });

        Ok(StartAppResponse {
            success: true,
            message: format!("Task created successfully. Use task_id to check status."),
            task_id: task_id,
            timestamp: crate::utils::current_timestamp(),
        })
    }

    /// Get task status
    pub async fn get_task_status(&self, task_id: &str) -> Option<Task> {
        self.task_manager.get_task(task_id).await
    }

    /// Get the hash algorithm currently in use
    pub fn get_hash_algorithm(&self) -> String {
        // Return the algorithm used by ComposeMeasurement
        let algo = HashAlgorithm::default();
        match algo {
            HashAlgorithm::Sha256 => "sha256".to_string(),
            HashAlgorithm::Sha384 => "sha384".to_string(),
        }
    }

    /// Get application logs from docker compose
    pub async fn get_app_logs(
        &self,
        app_id: &str,
        lines: i32,
        service_name: Option<&str>,
    ) -> TappResult<String> {
        DockerComposeManager::get_app_logs(app_id, lines, service_name).await
    }

    pub async fn get_evidence(
        &self,
        request: GetEvidenceRequest,
        signer_eth_address: &[u8],
        tls_public_key: Option<String>,
    ) -> TappResult<GetEvidenceResponse> {
        // Get app_id from request
        let app_id = request.app_id;
        if app_id.is_empty() {
            return Err(TappError::InvalidParameter {
                field: "app_id".to_string(),
                reason: "app_id cannot be empty".to_string(),
            });
        }

        // Ensure app exists
        {
            let app_info_lock = self.app_info.lock().await;
            if !app_info_lock.contains_key(&app_id) {
                return Err(TappError::InvalidParameter {
                    field: "app_id".to_string(),
                    reason: format!("App {} not found", app_id),
                });
            }
        }

        if request.nonce.len() > crate::report_data::MAX_NONCE_LEN {
            return Err(TappError::InvalidParameter {
                field: "nonce".to_string(),
                reason: format!(
                    "nonce must be at most {} bytes, got {}",
                    crate::report_data::MAX_NONCE_LEN,
                    request.nonce.len()
                ),
            });
        }

        // report_data commits to a small structure rather than to the signer alone, so
        // the caller's challenge (and later the app's TLS key) fit alongside it. The
        // structure travels with the quote — a quote on its own no longer names its
        // signer. See tapp_common::report_data.
        let mut runtime_data =
            crate::report_data::RuntimeData::new(signer_eth_address, &request.nonce)?;
        runtime_data.tls_public_key = tls_public_key.unwrap_or_default();
        let (runtime_data_bytes, report_data) = runtime_data.seal()?;

        info!(
            app_id = %app_id,
            signer = %runtime_data.signer,
            nonce_len = request.nonce.len(),
            report_data = %hex::encode(&report_data),
            "Generating evidence"
        );

        let evidence = self.measurement_service.get_evidence(&report_data).await?;
        let evidence = attach_runtime_data(evidence, &runtime_data_bytes);
        let tee_type = self.measurement_service.get_tee_type().await;
        Ok(GetEvidenceResponse {
            success: true,
            message: format!("Evidence generated successfully for app {}", app_id),
            evidence,
            tee_type,
            timestamp: crate::utils::current_timestamp(),
        })
    }

    /// Validate start app request
    fn validate_request(&self, request: &StartAppRequest) -> TappResult<()> {
        if request.compose_content.is_empty() {
            return Err(DockerError::InvalidComposeContent {
                reason: "Compose content cannot be empty".to_string(),
            }
            .into());
        }

        if request.app_id.is_empty() {
            return Err(DockerError::InvalidComposeContent {
                reason: "App ID cannot be empty".to_string(),
            }
            .into());
        }

        if !crate::utils::validate_app_id(&request.app_id) {
            return Err(DockerError::InvalidComposeContent {
                reason: format!("Invalid app ID format: {}", request.app_id),
            }
            .into());
        }

        // Warn-only for now (see compose_lint): existing apps use named volumes,
        // so this is a migration signal before it becomes a gate.
        for finding in compose_lint::lint_compose(&request.compose_content) {
            warn!(app_id = %request.app_id, "compose lint: {finding}");
        }

        Ok(())
    }

    /// Calculate application measurement
    async fn calculate_app_measurement(
        &self,
        request: &StartAppRequest,
        mount_files: &[MountFile],
        app_id: &str,
        deployer: &str,  // EVM address from signature
        operation: &str, // Operation name like "start_app"
        image_hash: std::collections::BTreeMap<String, String>, // Actual image digests from containers
    ) -> TappResult<(AppMeasurement, String, String)> {
        let measurement = ComposeMeasurement::new();

        // Calculate compose file hash
        let compose_hash = measurement.calculate_compose_hash(&request.compose_content)?;

        // Calculate volumes hash from mount files (uploaded files)
        let (volumes_hash, volumes_content) =
            measurement.calculate_mount_files_hash(mount_files)?;

        Ok((
            AppMeasurement {
                app_id: app_id.to_string(),
                operation: operation.to_string(),
                result: String::new(), // Will be set by with_success() or with_failure()
                error: None,           // Will be set by with_failure() if needed
                compose_hash,
                volumes_hash,
                image_hash,
                deployer: deployer.to_string(),
                timestamp: crate::utils::current_timestamp(),
            },
            request.compose_content.clone(),
            volumes_content,
        ))
    }

    pub async fn stop_app(&self, app_id: &str) -> TappResult<()> {
        info!(app_id = %app_id, "Stopping application");

        // Get AppInfo for this app (to use for stop operation measurement)
        let app_info = {
            let app_info_lock = self.app_info.lock().await;
            app_info_lock.get(app_id).cloned()
        };

        let app_info = match app_info {
            Some(info) => info,
            None => {
                return Err(TappError::InvalidParameter {
                    field: "app_id".to_string(),
                    reason: format!("App {} not found or not running", app_id),
                });
            }
        };

        // Create measurement for stop operation based on app info
        let base_measurement = AppMeasurement {
            app_id: app_id.to_string(),
            operation: crate::measurement_service::OPERATION_NAME_STOP_APP.to_string(),
            result: String::new(),
            error: None,
            compose_hash: app_info.compose_content.hash.clone(),
            volumes_hash: app_info.mount_files.hash.clone(),
            image_hash: app_info.compose_content.image_hash.clone(),
            deployer: app_info.owner.clone(),
            timestamp: crate::utils::current_timestamp(),
        };

        // Try to stop the application
        let result = DockerComposeManager::stop_compose(app_id).await;

        // Mark measurement as success or failure based on result
        let final_measurement = match &result {
            Ok(_) => {
                // 1. Remove app directory. The encrypted volume mounted at
                // <app_dir>/data must detach first or the removal hits EBUSY —
                // only the mount point is released; the LUKS mapping (and the
                // key in the kernel) stays open, and the volume's data lives in
                // the image file on /data, untouched. The next start remounts.
                volume::unmount(app_id).await?;
                let app_dir = DockerComposeManager::get_app_dir(app_id);
                if app_dir.exists() {
                    tokio::fs::remove_dir_all(&app_dir).await.map_err(|e| {
                        TappError::Docker(DockerError::ContainerOperationFailed {
                            operation: "delete_app_dir".to_string(),
                            reason: format!("Failed to delete app directory: {}", e),
                        })
                    })?;
                }
                // 2. Clear hash info on successful stop (keep owner info for permission checks)
                let mut app_info_lock = self.app_info.lock().await;
                if let Some(info) = app_info_lock.get_mut(app_id) {
                    info.compose_content.hash.clear();
                    info.compose_content.content.clear();
                    info.compose_content.image_hash.clear();
                    info.mount_files.hash.clear();
                    info.mount_files.content.clear();
                }
                info!(app_id = %app_id, "Application stopped successfully, hash info cleared");
                base_measurement.with_success()
            }
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Extend runtime measurement
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        info!("stop_app measurement_json: {}", measurement_json);

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                crate::measurement_service::OPERATION_NAME_STOP_APP,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement for stop operation: {}", e);
        }

        result
    }

    pub async fn get_app_info(&self, app_id: &str) -> TappResult<Option<AppInfo>> {
        let app_info = self.app_info.lock().await;
        Ok(app_info.get(app_id).cloned())
    }

    /// Summaries of all apps currently running on this server:
    /// (app_id, owner, compose_hash, image_count).
    pub async fn list_apps(&self) -> Vec<(String, String, String, usize)> {
        let app_info = self.app_info.lock().await;
        app_info
            .values()
            .map(|a| {
                (
                    a.app_id.clone(),
                    a.owner.clone(),
                    a.compose_content.hash.clone(),
                    a.compose_content.image_hash.len(),
                )
            })
            .collect()
    }

    /// Docker login to registry for pulling private images
    pub async fn docker_login(
        &self,
        registry: &str,
        username: &str,
        password: &str,
    ) -> TappResult<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        info!(
            registry = %registry,
            username = %username,
            "Executing docker login"
        );

        // Determine registry (default to Docker Hub if empty)
        let registry_arg = if registry.is_empty() {
            "docker.io"
        } else {
            registry
        };

        // Execute docker login command with password via stdin
        let mut child = Command::new("docker")
            .args(&[
                "login",
                registry_arg,
                "--username",
                username,
                "--password-stdin",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| DockerError::CommandFailed {
                command: "docker login".to_string(),
                reason: format!("Failed to spawn command: {}", e),
            })?;

        // Write password to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(password.as_bytes())
                .await
                .map_err(|e| DockerError::CommandFailed {
                    command: "docker login".to_string(),
                    reason: format!("Failed to write password: {}", e),
                })?;
            stdin.shutdown().await.ok();
        }

        // Wait for command to complete
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| DockerError::CommandFailed {
                command: "docker login".to_string(),
                reason: format!("Failed to wait for command: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                registry = %registry_arg,
                stderr = %stderr,
                "Docker login failed"
            );
            return Err(DockerError::CommandFailed {
                command: "docker login".to_string(),
                reason: format!("Login failed: {}", stderr),
            }
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        info!(
            registry = %registry_arg,
            output = %stdout.trim(),
            "Docker login successful"
        );

        Ok(())
    }

    /// Docker logout from registry
    pub async fn docker_logout(&self, registry: &str) -> TappResult<()> {
        use tokio::process::Command;

        info!(registry = %registry, "Executing docker logout");

        // Determine registry (default to Docker Hub if empty)
        let registry_arg = if registry.is_empty() {
            "docker.io"
        } else {
            registry
        };

        // Execute docker logout command
        let output = Command::new("docker")
            .args(&["logout", registry_arg])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| DockerError::CommandFailed {
                command: "docker logout".to_string(),
                reason: format!("Failed to execute: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                registry = %registry_arg,
                stderr = %stderr,
                "Docker logout failed"
            );
            return Err(DockerError::CommandFailed {
                command: "docker logout".to_string(),
                reason: format!("Logout failed: {}", stderr),
            }
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        info!(
            registry = %registry_arg,
            output = %stdout.trim(),
            "Docker logout successful"
        );

        Ok(())
    }

    /// Prune unused Docker images
    pub async fn prune_images(&self, all: bool) -> TappResult<PruneImagesResult> {
        DockerComposeManager::prune_images(all).await
    }

    /// Get application container status
    pub async fn get_app_container_status(&self, app_id: &str) -> TappResult<AppStatus> {
        DockerComposeManager::get_app_status(app_id).await
    }

    /// Docker logout from registry
    pub async fn stop_service(&self, app_id: &str, service_name: &str) -> TappResult<()> {
        info!(app_id = %app_id, service_name = %service_name, "Stopping service");

        // Get AppInfo for this app (to use for stop operation measurement)
        let app_info = {
            let app_info_lock = self.app_info.lock().await;
            app_info_lock.get(app_id).cloned()
        };

        let app_info = match app_info {
            Some(info) => info,
            None => {
                return Err(TappError::InvalidParameter {
                    field: "app_id".to_string(),
                    reason: format!("App {} not found or not running", app_id),
                });
            }
        };

        // Create measurement for stop operation based on app info
        let base_measurement = AppMeasurement {
            app_id: app_id.to_string(),
            operation: crate::measurement_service::OPERATION_NAME_STOP_APP.to_string(),
            result: String::new(),
            error: None,
            compose_hash: app_info.compose_content.hash.clone(),
            volumes_hash: app_info.mount_files.hash.clone(),
            image_hash: app_info.compose_content.image_hash.clone(),
            deployer: app_info.owner.clone(),
            timestamp: crate::utils::current_timestamp(),
        };

        // Try to stop the application
        let result = DockerComposeManager::stop_service(app_id, service_name).await;
        let final_measurement = match &result {
            Ok(_) => base_measurement.with_success(),
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Extend runtime measurement
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        info!("stop_service measurement_json: {}", measurement_json);

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                crate::measurement_service::OPERATION_NAME_STOP_SERVICE,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement for stop operation: {}", e);
        }

        result
    }

    /// Docker logout from registry
    pub async fn start_service(
        self: std::sync::Arc<Self>,
        app_id: String,
        service_name: String,
        pull_image: bool,
    ) -> TappResult<String> {
        // Validate that app exists
        {
            let app_info_lock = self.app_info.lock().await;
            if app_info_lock.get(&app_id).is_none() {
                return Err(TappError::InvalidParameter {
                    field: "app_id".to_string(),
                    reason: format!("App {} not found or not running", app_id),
                });
            }
        }

        // Create a new task
        let task = self.task_manager.create_task().await;
        let task_id = task.id.clone();

        info!(
            task_id = %task_id,
            app_id = %app_id,
            service_name = %service_name,
            "Created task for starting service"
        );

        // Mark task as running
        self.task_manager.mark_running(&task_id).await;

        // Clone Arc for background task
        let service = self.clone();
        let task_id_clone = task_id.clone();

        // Spawn background task
        tokio::spawn(async move {
            service
                ._start_service(app_id, service_name, pull_image, task_id_clone)
                .await;
        });

        Ok(task_id)
    }

    async fn _start_service(
        &self,
        app_id: String,
        service_name: String,
        pull_image: bool,
        task_id: String,
    ) {
        info!(
            task_id = %task_id,
            app_id = %app_id,
            service_name = %service_name,
            "Starting service"
        );

        // Get AppInfo for this app (to use for measurement)
        let app_info = {
            let app_info_lock = self.app_info.lock().await;
            app_info_lock.get(&app_id).cloned()
        };

        let app_info = match app_info {
            Some(info) => info,
            None => {
                let error_msg = format!("App {} not found or not running", app_id);
                tracing::error!(
                    task_id = %task_id,
                    app_id = %app_id,
                    "App not found"
                );
                self.task_manager.mark_failed(&task_id, error_msg).await;
                return;
            }
        };

        // Create measurement for start service operation based on app info
        let mut base_measurement = AppMeasurement {
            app_id: app_id.clone(),
            operation: crate::measurement_service::OPERATION_NAME_START_SERVICE.to_string(),
            result: String::new(),
            error: None,
            compose_hash: app_info.compose_content.hash.clone(),
            volumes_hash: app_info.mount_files.hash.clone(),
            image_hash: app_info.compose_content.image_hash.clone(),
            deployer: app_info.owner.clone(),
            timestamp: crate::utils::current_timestamp(),
        };

        // Try to start the service
        let result = DockerComposeManager::start_service(&app_id, &service_name, pull_image).await;

        // Update base_measurement with new image hash and handle result
        let final_measurement = match result {
            Ok(_) => {
                info!(
                    task_id = %task_id,
                    app_id = %app_id,
                    service_name = %service_name,
                    "Service started successfully"
                );

                // If image was pulled, update image hash
                if pull_image {
                    match DockerComposeManager::get_service_image(&app_id, &service_name).await {
                        Ok(Some(new_image_hash)) => {
                            // Update AppInfo with new image hash
                            let mut app_info_lock = self.app_info.lock().await;
                            if let Some(app_info) = app_info_lock.get_mut(&app_id) {
                                app_info
                                    .compose_content
                                    .image_hash
                                    .insert(service_name.clone(), new_image_hash.clone());
                                info!(
                                    task_id = %task_id,
                                    app_id = %app_id,
                                    service_name = %service_name,
                                    image_hash = %new_image_hash,
                                    "Updated image hash for service"
                                );
                            }
                            // Update measurement with new image hash
                            base_measurement
                                .image_hash
                                .insert(service_name.clone(), new_image_hash);
                        }
                        Ok(None) => {
                            warn!(
                                task_id = %task_id,
                                app_id = %app_id,
                                service_name = %service_name,
                                "Could not retrieve image hash for service"
                            );
                        }
                        Err(e) => {
                            warn!(
                                task_id = %task_id,
                                app_id = %app_id,
                                service_name = %service_name,
                                error = %e,
                                "Failed to get image hash for service"
                            );
                        }
                    }
                }

                // Mark task as completed
                self.task_manager
                    .mark_completed(
                        &task_id,
                        TaskSuccessResult {
                            app_id,
                            deployer: app_info.owner,
                            ..Default::default()
                        },
                    )
                    .await;

                base_measurement.with_success()
            }
            Err(e) => {
                tracing::error!(
                    task_id = %task_id,
                    app_id = %app_id,
                    service_name = %service_name,
                    error = %e,
                    "Failed to start service"
                );
                self.task_manager
                    .mark_failed(&task_id, format!("{}", e))
                    .await;

                base_measurement.with_failure(format!("{}", e))
            }
        };

        // Extend runtime measurement
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                crate::measurement_service::OPERATION_NAME_START_SERVICE,
                &measurement_json,
            )
            .await
        {
            tracing::error!(
                "Failed to extend measurement for start service operation: {}",
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {}
