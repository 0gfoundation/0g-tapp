use crate::error::{DockerError, TappResult, TappError};
use bollard::container::{ListContainersOptions, StopContainerOptions};
use bollard::models::ContainerInspectResponse;
use bollard::Docker;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{error, info, warn};

/// Application status
#[derive(Debug, Clone)]
pub struct AppStatus {
    pub app_id: String,
    pub running: bool,
    pub container_count: usize,
    pub containers: Vec<ContainerStatus>,
    pub started_at: Option<i64>,
}

/// Container status
#[derive(Debug, Clone)]
pub struct ContainerStatus {
    pub name: String,
    pub state: String,
    pub health: Option<String>,
    pub ports: Vec<String>,
}

/// Mount file configuration
#[derive(Debug, Clone)]
pub struct MountFile {
    pub source_path: String, // Source path from compose file (e.g., ./nginx.conf)
    pub content: Vec<u8>,
    pub mode: String,
}

/// Docker Compose manager for container lifecycle
pub struct DockerComposeManager {
    docker: Docker,
    app_containers: HashMap<String, Vec<String>>, // app_id -> container_names
}

/// Deployment result
#[derive(Debug, Clone)]
pub struct DeploymentResult {
    pub app_id: String,
    pub container_count: usize,
    pub container_names: Vec<String>,
    pub started_at: i64,
}

impl DockerComposeManager {
    /// Get the directory path for an app
    pub fn get_app_dir(&self, app_id: &str) -> PathBuf {
        PathBuf::from(format!("/var/lib/tapp/apps/{}", app_id))
    }

    /// Create new Docker Compose manager
    pub async fn new(docker_socket: &str) -> TappResult<Self> {
        let docker = if docker_socket.starts_with("unix://") || docker_socket.starts_with("/") {
            Docker::connect_with_socket_defaults().map_err(|_e| DockerError::ConnectionFailed)?
        } else {
            Docker::connect_with_http_defaults().map_err(|_e| DockerError::ConnectionFailed)?
        };

        // Test connection
        docker
            .ping()
            .await
            .map_err(|_| DockerError::ConnectionFailed)?;

        info!("Connected to Docker daemon");

        Ok(Self {
            docker,
            app_containers: HashMap::new(),
        })
    }

    /// Create mock manager for testing
    pub fn mock() -> Self {
        // This will fail if actually used, but good for testing structure
        Self {
            docker: Docker::connect_with_socket_defaults().unwrap_or_else(|_| {
                // This is a hack for testing - in real tests we'd use a proper mock
                panic!("Mock Docker not available")
            }),
            app_containers: HashMap::new(),
        }
    }

    /// Store mount files to host filesystem and create mapping
    /// Returns a HashMap of source_path -> actual_host_path
    async fn store_mount_files(
        &self,
        base_path: &PathBuf,
        mount_files: &[MountFile],
    ) -> TappResult<HashMap<String, String>> {
        let mut source_to_host = HashMap::new();

        for mount_file in mount_files {
            // Sanitize source path for storage (remove ./ prefix, convert / to _)
            let sanitized = mount_file
                .source_path
                .trim_start_matches("./")
                .trim_start_matches('/')
                .replace('/', "_");

            let host_path = base_path.join(&sanitized);

            // Create parent directories if needed
            if let Some(parent) = host_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    DockerError::VolumeMeasurementFailed {
                        path: format!("Failed to create parent directory: {}", e),
                    }
                })?;
            }

            // Write file content
            let mut file = fs::File::create(&host_path).await.map_err(|e| {
                DockerError::VolumeMeasurementFailed {
                    path: format!("Failed to create file {}: {}", host_path.display(), e),
                }
            })?;

            file.write_all(&mount_file.content).await.map_err(|e| {
                DockerError::VolumeMeasurementFailed {
                    path: format!("Failed to write file {}: {}", host_path.display(), e),
                }
            })?;

            // Set file permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = u32::from_str_radix(&mount_file.mode, 8).unwrap_or(0o644);
                let permissions = std::fs::Permissions::from_mode(mode);
                std::fs::set_permissions(&host_path, permissions).map_err(|e| {
                    DockerError::VolumeMeasurementFailed {
                        path: format!(
                            "Failed to set permissions on {}: {}",
                            host_path.display(),
                            e
                        ),
                    }
                })?;
            }

            info!(
                source_path = %mount_file.source_path,
                host_path = %host_path.display(),
                size = mount_file.content.len(),
                "Stored mount file"
            );

            // Map source path to actual host path
            source_to_host.insert(
                mount_file.source_path.clone(),
                host_path.to_string_lossy().to_string(),
            );
        }

        Ok(source_to_host)
    }

    /// Deploy Docker Compose application
    pub async fn deploy_compose(
        &mut self,
        app_id: &str,
        compose_content: &str,
        mount_files: &[MountFile],
    ) -> TappResult<()> {
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::sync::Mutex;

        // 1. store compose file
        let base_path = self.get_app_dir(app_id);
        if !base_path.exists() {
            fs::create_dir_all(&base_path).await.map_err(|e| {
                DockerError::VolumeMeasurementFailed {
                    path: format!("Failed to create volumes directory: {}", e),
                }
            })?;
        }
        let compose_path = base_path.join("docker-compose.yml");
        fs::write(&compose_path, compose_content).await?;

        // 2. store mount files to corresponding location
        self.store_mount_files(&base_path, mount_files).await?;

        // 3. start compose with real-time output
        info!(app_id = %app_id, "🚀 Starting docker compose up");

        let mut child = Command::new("docker")
            .current_dir(&base_path)
            .args(["compose", "-f", "docker-compose.yml", "up", "-d"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_compose_up".to_string(),
                reason: format!("Failed to execute docker compose command: {}", e),
            })?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Collect output
        let stdout_lines = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines = Arc::new(Mutex::new(Vec::new()));

        let app_id_clone = app_id.to_string();
        let stdout_lines_clone = stdout_lines.clone();
        let stdout_task = tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(
                    app_id = %app_id_clone,
                    output_type = "stdout",
                    "🐳 {}", line
                );
                stdout_lines_clone.lock().await.push(line);
            }
        });

        let app_id_clone = app_id.to_string();
        let stderr_lines_clone = stderr_lines.clone();
        let stderr_task = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(
                    app_id = %app_id_clone,
                    "🐳 {}", line
                );
                stderr_lines_clone.lock().await.push(line);
            }
        });

        let status = child
            .wait()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_compose_up".to_string(),
                reason: format!("Failed to wait for docker compose: {}", e),
            })?;

        let _ = tokio::join!(stdout_task, stderr_task);

        let all_stdout = stdout_lines.lock().await.join("\n");
        let all_stderr = stderr_lines.lock().await.join("\n");

        if !status.success() {
            error!(
                app_id = %app_id,
                exit_code = ?status.code(),
                stderr = %all_stderr,
                stdout = %all_stdout,
                "❌ Docker compose command failed"
            );

            return Err(DockerError::ContainerOperationFailed {
                operation: "docker_compose_up".to_string(),
                reason: format!(
                    "Docker compose failed with exit code {:?}\nStderr: {}\nStdout: {}",
                    status.code(),
                    all_stderr,
                    all_stdout
                ),
            }
            .into());
        }

        info!(
            app_id = %app_id,
            output = %all_stdout,
            "✅ Docker compose up completed successfully"
        );

        Ok(())
    }

    /// Stop Docker Compose application
    pub async fn stop_compose(&mut self, app_id: &str) -> TappResult<()> {
        info!(app_id = %app_id, "Stopping Docker Compose application");

        let container_names = self
            .app_containers
            .get(app_id)
            .ok_or_else(|| DockerError::ServiceNotFound {
                service_name: app_id.to_string(),
            })?
            .clone();

        for container_name in &container_names {
            match self.stop_container(container_name).await {
                Ok(_) => {
                    info!(container_name = %container_name, "Container stopped");
                }
                Err(e) => {
                    error!(
                        container_name = %container_name,
                        error = %e,
                        "Failed to stop container"
                    );
                }
            }
        }

        // Remove from tracking
        self.app_containers.remove(app_id);

        info!(app_id = %app_id, "Docker Compose application stopped");
        Ok(())
    }

    /// Stop and remove a single container
    async fn stop_container(&self, container_name: &str) -> TappResult<()> {
        // Stop container
        self.docker
            .stop_container(
                container_name,
                Some(StopContainerOptions {
                    t: 10, // 10 second timeout
                }),
            )
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "stop".to_string(),
                reason: format!("Failed to stop container {}: {}", container_name, e),
            })?;

        // Remove container
        self.docker
            .remove_container(container_name, None)
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "remove".to_string(),
                reason: format!("Failed to remove container {}: {}", container_name, e),
            })?;

        Ok(())
    }

    /// Get status of Docker Compose application
    pub async fn get_compose_status(&self, app_id: &str) -> TappResult<AppStatus> {
        let container_names =
            self.app_containers
                .get(app_id)
                .ok_or_else(|| DockerError::ServiceNotFound {
                    service_name: app_id.to_string(),
                })?;

        let mut containers = Vec::new();
        let mut running_count = 0;
        let mut started_at = None;

        for container_name in container_names {
            match self.get_container_status(container_name).await {
                Ok(status) => {
                    if status.state == "running" {
                        running_count += 1;
                    }
                    containers.push(status);
                }
                Err(e) => {
                    warn!(
                        container_name = %container_name,
                        error = %e,
                        "Failed to get container status"
                    );

                    containers.push(ContainerStatus {
                        name: container_name.clone(),
                        state: "unknown".to_string(),
                        health: None,
                        ports: Vec::new(),
                    });
                }
            }
        }

        // Get the earliest start time
        if let Some(first_container) = container_names.first() {
            if let Ok(inspect) = self.docker.inspect_container(first_container, None).await {
                if let Some(state) = inspect.state {
                    if let Some(started_time) = state.started_at {
                        if let Ok(parsed_time) = chrono::DateTime::parse_from_rfc3339(&started_time)
                        {
                            started_at = Some(parsed_time.timestamp());
                        }
                    }
                }
            }
        }

        Ok(AppStatus {
            app_id: app_id.to_string(),
            running: running_count > 0,
            container_count: containers.len(),
            containers,
            started_at,
        })
    }

    /// Get status of a single container
    async fn get_container_status(&self, container_name: &str) -> TappResult<ContainerStatus> {
        let inspect: ContainerInspectResponse = self
            .docker
            .inspect_container(container_name, None)
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "inspect".to_string(),
                reason: format!("Failed to inspect container {}: {}", container_name, e),
            })?;

        let state = inspect
            .state
            .as_ref()
            .and_then(|s| s.status.as_ref())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let health = inspect
            .state
            .as_ref()
            .and_then(|s| s.health.as_ref())
            .and_then(|h| h.status.as_ref())
            .map(|s| s.to_string());

        // Extract port information (simplified)
        let ports = Vec::new(); // TODO: Implement proper port extraction

        Ok(ContainerStatus {
            name: container_name.to_string(),
            state,
            health,
            ports,
        })
    }

    /// List running Docker Compose applications
    pub async fn list_running_composes(&self) -> TappResult<Vec<String>> {
        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: false,
                filters: {
                    let mut filters = HashMap::new();
                    filters.insert("label".to_string(), vec!["tapp.managed=true".to_string()]);
                    filters
                },
                ..Default::default()
            }))
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "list".to_string(),
                reason: format!("Failed to list containers: {}", e),
            })?;

        let mut app_ids = std::collections::HashSet::new();

        for container in containers {
            if let Some(labels) = container.labels {
                if let Some(app_id) = labels.get("tapp.app_id") {
                    app_ids.insert(app_id.clone());
                }
            }
        }

        Ok(app_ids.into_iter().collect())
    }

    /// Get application logs from docker compose
    pub async fn get_app_logs(
        &self,
        app_id: &str,
        lines: i32,
        service_name: Option<&str>,
    ) -> TappResult<String> {
        let app_dir = self.get_app_dir(app_id);

        if !app_dir.exists() {
            return Err(TappError::InvalidParameter {
                field: "app_id".to_string(),
                reason: format!("App {} not found", app_id),
            });
        }

        // Build docker compose logs command
        let lines_arg = if lines > 0 {
            lines.to_string()
        } else {
            "100".to_string()
        };

        let mut args = vec!["compose", "logs", "--tail", &lines_arg];

        // Add service name if specified
        if let Some(svc) = service_name {
            if !svc.is_empty() {
                args.push(svc);
            }
        }

        // Execute command in app directory
        let output = tokio::process::Command::new("docker")
            .args(&args)
            .current_dir(&app_dir)
            .output()
            .await
            .map_err(|e| {
                TappError::Docker(DockerError::ContainerOperationFailed {
                    operation: "get logs".to_string(),
                    reason: format!("Failed to execute docker compose logs: {}", e),
                })
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TappError::Docker(DockerError::ContainerOperationFailed {
                operation: "get logs".to_string(),
                reason: format!("docker compose logs failed: {}", stderr),
            }));
        }

        let logs = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(logs)
    }
}

#[cfg(test)]
mod tests {}

