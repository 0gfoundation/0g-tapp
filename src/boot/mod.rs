pub mod manager;
pub mod measurement;
pub mod task_manager;

pub use manager::{AppStatus, ContainerStatus, DockerComposeManager, MountFile};
pub use measurement::{AppMeasurement, ComposeMeasurement, HashAlgorithm};
pub use task_manager::{Task, TaskManager, TaskStatus as TaskState, TaskSuccessResult};

use crate::config::BootServiceConfig;
use crate::error::{DockerError, TappError, TappResult};
use crate::proto::{GetEvidenceRequest, GetEvidenceResponse, StartAppRequest, StartAppResponse};
use attestation_agent::{AttestationAPIs, AttestationAgent};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::Mutex;
use tracing::info;

pub const ZGEL_DOMAIN: &str = "tapp.0g.com";
pub const OPERATION_NAME_START_APP: &str = "start_app";
pub const OPERATION_NAME_STOP_APP: &str = "stop_app";

pub struct BootService {
    config: BootServiceConfig,
    manager: Mutex<DockerComposeManager>,
    app_measurements: Mutex<HashMap<String, AppMeasurement>>,
    aa: Mutex<AttestationAgent>,
    task_manager: TaskManager,
    app_compose_content: Mutex<HashMap<String, String>>,
    app_mount_files: Mutex<HashMap<String, String>>,
}

impl BootService {
    /// Ensure attestation agent config file exists with default values
    fn ensure_aa_config(config_path: &str) -> TappResult<()> {
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
    pub async fn new(config: &BootServiceConfig) -> TappResult<Self> {
        let manager = DockerComposeManager::new(&config.socket_path).await?;

        // Ensure AA config exists with defaults
        if let Some(ref aa_config_path) = config.aa_config_path {
            Self::ensure_aa_config(aa_config_path)?;
        }

        let mut aa = AttestationAgent::new(config.aa_config_path.as_deref()).unwrap();
        aa.init().await.unwrap();
        info!("Detected TEE type: {:?}", aa.get_tee_type());
        Ok(Self {
            config: config.clone(),
            manager: Mutex::new(manager),
            app_measurements: Mutex::new(HashMap::new()),
            aa: Mutex::new(aa),
            task_manager: TaskManager::new(),
            app_compose_content: Mutex::new(HashMap::new()),
            app_mount_files: Mutex::new(HashMap::new()),
        })
    }

    /// Internal method to handle the actual app start logic
    async fn _start_app(&self, request: StartAppRequest, task_id: String) {
        let result = async {
            let app_id = request.app_id.clone();
            if self.app_measurements.lock().await.contains_key(&app_id) {
                return Err(TappError::InvalidParameter {
                    field: "app_id".to_string(),
                    reason: format!("Application {} already exists", app_id),
                }
                .into());
            }

            info!(
                task_id = %task_id,
                app_id = %app_id,
                mount_files_count = request.mount_files.len(),
                "Starting application with Docker Compose"
            );

            // Convert proto MountFile to our MountFile structure
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

            // Calculate application measurement
            let (measurement, compose_content, volumes_content) = self
                .calculate_app_measurement(&request, &mount_files, &app_id)
                .await?;

            let measurement_json = serde_json::to_string(&measurement)?;
            info!("measurement_json: {}", measurement_json);

            self.app_compose_content
                .lock()
                .await
                .insert(app_id.clone(), compose_content);

            self.app_mount_files
                .lock()
                .await
                .insert(app_id.clone(), volumes_content);

            // Start the Docker Compose application with mount files
            self.manager
                .lock()
                .await
                .deploy_compose(&app_id, &request.compose_content, &mount_files)
                .await?;

            // Store measurement in memory
            self.app_measurements
                .lock()
                .await
                .insert(app_id.clone(), measurement.clone());

            self.aa
                .lock()
                .await
                .extend_runtime_measurement(
                    ZGEL_DOMAIN,
                    OPERATION_NAME_START_APP,
                    &measurement_json,
                    None,
                )
                .await?;

            info!(
                task_id = %task_id,
                app_id = %app_id,
                "Application started successfully"
            );

            Ok::<_, crate::error::TappError>((app_id, request.deployer))
        }
        .await;

        // Update task status based on result
        match result {
            Ok((app_id, deployer)) => {
                self.task_manager
                    .mark_completed(&task_id, TaskSuccessResult { app_id, deployer })
                    .await;
            }
            Err(e) => {
                self.task_manager
                    .mark_failed(&task_id, format!("{}", e))
                    .await;
            }
        }
    }

    /// Handle start app request (async - returns task ID immediately)
    /// This method should be called with Arc<Self> from the service implementation
    pub async fn start_app(
        self: std::sync::Arc<Self>,
        request: StartAppRequest,
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
            service._start_app(request, task_id_clone).await;
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

    /// List all app measurements
    pub async fn list_app_measurements(
        &self,
        deployer_filter: Option<String>,
    ) -> Vec<AppMeasurement> {
        let measurements = self.app_measurements.lock().await;

        let mut result: Vec<AppMeasurement> = measurements
            .values()
            .filter(|m| {
                // Apply deployer filter if provided
                if let Some(ref filter) = deployer_filter {
                    // Filter can be with or without 0x prefix
                    let filter_normalized = filter.trim_start_matches("0x").to_lowercase();
                    m.deployer.to_lowercase().contains(&filter_normalized)
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Sort by timestamp descending (newest first)
        result.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        result
    }

    pub async fn get_evidence(
        &self,
        request: GetEvidenceRequest,
    ) -> TappResult<GetEvidenceResponse> {
        // Prepare report data
        let report_data = if request.report_data.is_empty() {
            // Use zero-filled 64 bytes as default
            vec![0u8; 64]
        } else {
            // Validate and pad report data to 64 bytes
            if request.report_data.len() > 64 {
                return Err(DockerError::InvalidComposeContent {
                    reason: format!(
                        "Report data must be at most 64 bytes, got {}",
                        request.report_data.len()
                    ),
                }
                .into());
            }
            let mut padded = request.report_data.clone();
            padded.resize(64, 0);
            padded
        };

        info!("report_data: {:?}", hex::encode(&report_data));

        let evidence = self.aa.lock().await.get_evidence(&report_data).await?;
        Ok(GetEvidenceResponse {
            success: true,
            message: "Evidence generated successfully".to_string(),
            evidence: evidence,
            tee_type: format!("{:?}", self.aa.lock().await.get_tee_type()),
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

        if request.deployer.len() != 64 {
            return Err(DockerError::InvalidComposeContent {
                reason: "Deployer must be 64 bytes".to_string(),
            }
            .into());
        }

        Ok(())
    }

    /// Calculate application measurement
    async fn calculate_app_measurement(
        &self,
        request: &StartAppRequest,
        mount_files: &[MountFile],
        app_id: &str,
    ) -> TappResult<(AppMeasurement, String, String)> {
        let measurement = ComposeMeasurement::new();

        // Calculate compose file hash
        // println!("compose_content: {}", request.compose_content);
        let compose_hash = measurement.calculate_compose_hash(&request.compose_content)?;
        // println!("compose_hash: {:?}", compose_hash);

        // Calculate volumes hash from mount files (uploaded files)
        // This is the key change: now we calculate hash from actual file contents
        // println!("mount_files: {:?}", mount_files);
        let (volumes_hash, volumes_content) =
            measurement.calculate_mount_files_hash(mount_files)?;
        // println!("volumes_hash: {:?}", volumes_hash);

        Ok((
            AppMeasurement {
                app_id: app_id.to_string(),
                compose_hash,
                volumes_hash,
                deployer: hex::encode(request.deployer.clone()),
                timestamp: crate::utils::current_timestamp(),
            },
            request.compose_content.clone(),
            volumes_content,
        ))
    }

    /// Stop application
    pub async fn stop_app(&self, app_id: &str) -> TappResult<()> {
        info!(app_id = %app_id, "Stopping application");

        self.manager.lock().await.stop_compose(app_id).await?;

        info!(app_id = %app_id, "Application stopped successfully");
        Ok(())
    }

    /// Get application status
    pub async fn get_app_status(&self, app_id: &str) -> TappResult<AppStatus> {
        self.manager.lock().await.get_compose_status(app_id).await
    }

    /// List running applications
    pub async fn list_apps(&self) -> TappResult<Vec<String>> {
        self.manager.lock().await.list_running_composes().await
    }

    pub async fn get_app_compose_content(&self, app_id: &str) -> TappResult<Option<String>> {
        let compose_content = self.app_compose_content.lock().await.get(app_id).cloned();
        Ok(compose_content)
    }

    pub async fn get_app_mount_files(&self, app_id: &str) -> TappResult<Option<String>> {
        let mount_files = self.app_mount_files.lock().await.get(app_id).cloned();
        Ok(mount_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::sync::Arc;

    fn create_test_request() -> StartAppRequest {
        StartAppRequest {
            compose_content: r#"
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
volumes:
  data:
    driver: local
"#
            .to_string(),
            app_id: "test-nginx-app".to_string(),
            mount_files: vec![],
            deployer: vec![0; 32],
        }
    }

    fn create_real_request() -> StartAppRequest {
        StartAppRequest {
            compose_content: r#"
    version: '3.8'
    services:
      hello:
        image: hello-world
    volumes:
      data:
        driver: local
    "#
            .to_string(),
            app_id: "test-hello-app".to_string(),
            mount_files: vec![],
            deployer: vec![0; 32],
        }
    }

    fn create_request_with_mount_files() -> StartAppRequest {
        use crate::proto::MountFile as ProtoMountFile;

        StartAppRequest {
            compose_content: r#"
version: '3.8'
services:
  web:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./config.json:/app/config.json:ro
"#
            .to_string(),
            app_id: "test-nginx-app".to_string(),
            mount_files: vec![
                ProtoMountFile {
                    source_path: "./nginx.conf".to_string(),
                    content: b"user nginx;\nworker_processes 1;\n".to_vec(),
                    mode: "0644".to_string(),
                },
                ProtoMountFile {
                    source_path: "./config.json".to_string(),
                    content: b"{\"key\": \"value\", \"enabled\": true}".to_vec(),
                    mode: "0644".to_string(),
                },
            ],
            deployer: vec![0; 32],
        }
    }

    #[test]
    fn test_validate_request() {
        let service = BootService {
            config: BootServiceConfig::default(),
            manager: Mutex::new(DockerComposeManager::mock()),
            app_measurements: Mutex::new(HashMap::new()),
            aa: Mutex::new(AttestationAgent::new(None).unwrap()),
            task_manager: TaskManager::new(),
            app_compose_content: Mutex::new(HashMap::new()),
            app_mount_files: Mutex::new(HashMap::new()),
        };

        // Valid request
        let request = create_test_request();
        assert!(service.validate_request(&request).is_ok());

        // Invalid - empty compose content
        let mut invalid_request = create_test_request();
        invalid_request.compose_content = "".to_string();
        assert!(service.validate_request(&invalid_request).is_err());

        // Invalid - empty app ID
        let mut invalid_request = create_test_request();
        invalid_request.app_id = "".to_string();
        assert!(service.validate_request(&invalid_request).is_err());
    }

    #[tokio::test]
    async fn test_start_app() {
        let config = BootServiceConfig {
            socket_path: "/var/run/docker.sock".to_string(),
            ..Default::default()
        };
        let service = Arc::new(BootService::new(&config).await.unwrap());
        let request = create_real_request();
        let response = service.start_app(request).await.unwrap();
        assert!(response.success);
    }

    #[tokio::test]
    async fn test_start_app_with_mount_files() {
        let config = BootServiceConfig {
            socket_path: "/var/run/docker.sock".to_string(),
            ..Default::default()
        };
        let service = Arc::new(BootService::new(&config).await.unwrap());
        let request = create_request_with_mount_files();
        let response = service.start_app(request).await.unwrap();
        assert!(response.success);
    }

    #[tokio::test]
    async fn test_get_evidence() {
        let config = BootServiceConfig {
            socket_path: "/var/run/docker.sock".to_string(),
            ..Default::default()
        };
        let service = Arc::new(BootService::new(&config).await.unwrap());

        service
            .clone()
            .start_app(create_request_with_mount_files())
            .await
            .unwrap();

        // Create custom report data (e.g., a nonce or hash)
        let custom_data = b"test-nonce-12345678";
        let request = GetEvidenceRequest {
            report_data: custom_data.to_vec(),
        };
        let response = service.get_evidence(request).await.unwrap();

        let evidence_json =
            serde_json::to_string(&String::from_utf8(response.evidence).unwrap()).unwrap();
        let file = File::create("evidence.json").unwrap();
        serde_json::to_writer(file, &evidence_json).unwrap();
        assert!(response.success);
    }
}
