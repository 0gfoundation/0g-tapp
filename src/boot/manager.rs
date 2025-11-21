use crate::error::{DockerError, TappError, TappResult};
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
    pub fn get_app_dir(app_id: &str) -> PathBuf {
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
        app_id: &str,
        compose_content: &str,
        mount_files: &[MountFile],
    ) -> TappResult<()> {
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::sync::Mutex;

        // 1. store compose file
        let base_path = Self::get_app_dir(app_id);
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
        Self::store_mount_files(&base_path, mount_files).await?;

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
    pub async fn stop_compose(app_id: &str) -> TappResult<()> {
        let app_dir = Self::get_app_dir(app_id);

        if !app_dir.exists() {
            return Err(TappError::InvalidParameter {
                field: "app_id".to_string(),
                reason: format!("App {} not found", app_id),
            });
        }

        info!(app_id = %app_id, "🛑 Stopping Docker Compose application");

        // Execute docker compose down in app directory
        let output = tokio::process::Command::new("docker")
            .args(&["compose", "down"])
            .current_dir(&app_dir)
            .output()
            .await
            .map_err(|e| {
                TappError::Docker(DockerError::ContainerOperationFailed {
                    operation: "stop".to_string(),
                    reason: format!("Failed to execute docker compose down: {}", e),
                })
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                app_id = %app_id,
                stderr = %stderr,
                "❌ Docker compose down failed"
            );
            return Err(TappError::Docker(DockerError::ContainerOperationFailed {
                operation: "stop".to_string(),
                reason: format!("docker compose down failed: {}", stderr),
            }));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        info!(
            app_id = %app_id,
            output = %stdout,
            "✅ Docker compose down completed successfully"
        );

        Ok(())
    }

    /// Get application logs from docker compose
    pub async fn get_app_logs(
        app_id: &str,
        lines: i32,
        service_name: Option<&str>,
    ) -> TappResult<String> {
        info!(
            app_id = %app_id,
            lines = lines,
            service_name = ?service_name,
            "Getting application logs"
        );

        let app_dir = Self::get_app_dir(app_id);

        if !app_dir.exists() {
            warn!(app_id = %app_id, "App directory not found");
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
