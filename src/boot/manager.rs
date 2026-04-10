use crate::error::{DockerError, TappError, TappResult};
use chrono;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::fs;
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
pub struct DockerComposeManager;

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

    /// Store mount files to host filesystem and create mapping
    /// Returns a HashMap of source_path -> actual_host_path
    async fn store_mount_files(
        base_path: &PathBuf,
        mount_files: &[MountFile],
    ) -> TappResult<HashMap<String, String>> {
        let mut source_to_host = HashMap::new();

        for mount_file in mount_files {
            // Normalize source path: remove leading ./ or / to get a relative path
            // Preserve directory structure so docker compose can find files at their original paths
            let relative = mount_file
                .source_path
                .trim_start_matches("./")
                .trim_start_matches('/');

            let host_path = base_path.join(relative);

            // Ensure the resolved path stays within base_path (prevent directory traversal)
            let canonical_base = base_path.canonicalize().unwrap_or_else(|_| base_path.clone());
            let canonical_host = host_path
                .parent()
                .and_then(|p| p.canonicalize().ok())
                .unwrap_or_else(|| host_path.parent().unwrap_or(base_path).to_path_buf());
            if !canonical_host.starts_with(&canonical_base) {
                warn!(
                    source_path = %mount_file.source_path,
                    "Skipping mount file: path escapes app directory"
                );
                continue;
            }

            // Create parent directories if needed
            if let Some(parent) = host_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    DockerError::VolumeMeasurementFailed {
                        path: format!("Failed to create parent directory: {}", e),
                    }
                })?;
            }

            // Write file content atomically in a single blocking task
            let content = mount_file.content.clone();
            let write_path = host_path.clone();
            fs::write(&write_path, &content).await.map_err(|e| {
                DockerError::VolumeMeasurementFailed {
                    path: format!("Failed to write file {}: {}", write_path.display(), e),
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
    ) -> TappResult<std::collections::BTreeMap<String, String>> {
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

        let image_map = Self::get_container_images(app_id).await?;
        Ok(image_map)
    }

    /// Get image hashes from running containers
    pub async fn get_container_images(
        app_id: &str,
    ) -> TappResult<std::collections::BTreeMap<String, String>> {
        use serde::Deserialize;

        let app_dir = Self::get_app_dir(app_id);

        // Execute: docker compose images --format json
        let output = Command::new("docker")
            .current_dir(&app_dir)
            .args(["compose", "images", "--format", "json"])
            .output()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_compose_images".to_string(),
                reason: format!("Failed to execute docker compose images: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DockerError::ContainerOperationFailed {
                operation: "docker_compose_images".to_string(),
                reason: format!("Command failed: {}", stderr),
            }
            .into());
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ImageInfo {
            #[serde(rename = "ID")]
            id: String,
            container_name: String,
        }

        // docker compose images --format json outputs a JSON array
        let stdout = String::from_utf8_lossy(&output.stdout);
        let images: Vec<ImageInfo> = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            warn!(
                error = %e,
                output = %stdout,
                "Failed to parse docker compose images JSON output"
            );
            Vec::new()
        });

        // Build map: service_name -> ContainerImageInfo
        let mut image_map = std::collections::BTreeMap::new();

        for img in images {
            // Extract service name from container name
            let service_name =
                if let Some(stripped) = img.container_name.strip_prefix(&format!("{}-", app_id)) {
                    stripped
                        .rsplit_once('-')
                        .and_then(|(name, suffix)| {
                            if suffix.chars().all(|c| c.is_numeric()) {
                                Some(name)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(stripped)
                        .to_string()
                } else {
                    img.container_name.clone()
                };

            // Get digest from docker inspect
            let digest = Self::get_image_digest(&img.id).await.unwrap_or_else(|e| {
                warn!(
                    image_id = %img.id,
                    error = %e,
                    "Failed to get image digest"
                );
                String::new()
            });

            image_map.insert(service_name, digest.clone());
        }

        info!(
            app_id = %app_id,
            image_count = image_map.len(),
            "📦 Retrieved container image information"
        );

        Ok(image_map)
    }

    async fn get_image_digest(image_id: &str) -> TappResult<String> {
        let output = Command::new("docker")
            .args(["inspect", "--format={{index .RepoDigests 0}}", image_id])
            .output()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_inspect".to_string(),
                reason: format!("Failed to inspect image: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                image_id = %image_id,
                stderr = %stderr,
                "Failed to get digest from docker inspect"
            );
            return Ok(String::new());
        }

        let digest_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // 如果没有 RepoDigests（可能是本地构建的镜像）
        if digest_str.is_empty() || digest_str == "<no value>" {
            return Ok(String::new());
        }

        // Extract digest part (format: "repo@sha256:...")
        let digest = digest_str.split('@').nth(1).unwrap_or("").to_string();

        Ok(digest)
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
        // If lines <= 0, get all logs (no --tail parameter)
        let mut args: Vec<String> = vec!["compose".to_string(), "logs".to_string()];
        if lines > 0 {
            args.push("--tail".to_string());
            args.push(lines.to_string());
        }

        // Add service name if specified
        if let Some(svc) = service_name {
            if !svc.is_empty() {
                args.push(svc.to_string());
            }
        }

        // Execute command in app directory
        let output = tokio::process::Command::new("docker")
            .args(args.iter().map(|s| s.as_str()))
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

    /// Stop a specific service within an app
    pub async fn stop_service(app_id: &str, service_name: &str) -> TappResult<()> {
        let app_dir = Self::get_app_dir(app_id);

        let output = tokio::process::Command::new("docker")
            .args(&["compose", "stop", service_name])
            .current_dir(&app_dir)
            .output()
            .await
            .map_err(|e| {
                TappError::Docker(DockerError::ContainerOperationFailed {
                    operation: "stop_service".to_string(),
                    reason: format!("Failed to execute docker compose stop: {}", e),
                })
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                app_id = %app_id,
                stderr = %stderr,
                "❌ Docker stop service failed"
            );
            return Err(TappError::Docker(DockerError::ContainerOperationFailed {
                operation: "stop".to_string(),
                reason: format!("docker stop service failed: {}", stderr),
            }));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        info!(
            app_id = %app_id,
            output = %stdout,
            "✅ Docker stop service completed successfully"
        );

        Ok(())
    }

    /// Check if a service is running
    pub async fn is_service_running(app_id: &str, service_name: &str) -> TappResult<bool> {
        let app_dir = Self::get_app_dir(app_id);

        if !app_dir.exists() {
            return Ok(false);
        }

        // Execute: docker compose ps --services --filter "status=running" --format json
        let output = tokio::process::Command::new("docker")
            .args(&[
                "compose",
                "ps",
                "--services",
                "--filter",
                "status=running",
                "--format",
                "json",
            ])
            .current_dir(&app_dir)
            .output()
            .await
            .map_err(|e| {
                TappError::Docker(DockerError::ContainerOperationFailed {
                    operation: "check_service_status".to_string(),
                    reason: format!("Failed to execute docker compose ps: {}", e),
                })
            })?;

        if !output.status.success() {
            // If command fails, assume service is not running
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Check if service_name appears in the output
        Ok(stdout.contains(service_name))
    }

    /// Get image hash for a specific service
    pub async fn get_service_image(app_id: &str, service_name: &str) -> TappResult<Option<String>> {
        let image_map = Self::get_container_images(app_id).await?;
        Ok(image_map.get(service_name).cloned())
    }

    /// Get list of failed/exited container service names
    /// Returns service names (not container names) that are in failed states
    pub async fn get_failed_services(app_id: &str) -> TappResult<Vec<String>> {
        use serde::Deserialize;

        let app_dir = Self::get_app_dir(app_id);

        if !app_dir.exists() {
            return Ok(Vec::new());
        }

        // Execute: docker compose ps --format json
        let output = Command::new("docker")
            .current_dir(&app_dir)
            .args(["compose", "ps", "--format", "json"])
            .output()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "get_failed_services".to_string(),
                reason: format!("Failed to execute docker compose ps: {}", e),
            })?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut failed_services = Vec::new();

        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ContainerInfo {
            name: String,
            state: String,
            service: Option<String>,
        }

        // Parse each line as JSON (docker compose ps outputs one JSON object per line)
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(container) = serde_json::from_str::<ContainerInfo>(line) {
                // Check if container is in a failed state
                // States: exited, dead, restarting (if restarting too many times)
                let state_lower = container.state.to_lowercase();
                if state_lower == "exited" || state_lower == "dead" {
                    // Extract service name from container name or use service field
                    // Container name format is usually: <app_id>_<service>_<number>
                    // Or we can use the service field if available
                    if let Some(service) = container.service {
                        if !failed_services.contains(&service) {
                            failed_services.push(service);
                        }
                    } else {
                        // Try to extract service name from container name
                        // Format: <app_id>-<service>-<number> or <app_id>_<service>_<number>
                        let parts: Vec<&str> = container.name.split('-').collect();
                        if parts.len() >= 2 {
                            let service = parts[1].to_string();
                            if !failed_services.contains(&service) {
                                failed_services.push(service);
                            }
                        }
                    }
                }
            }
        }

        Ok(failed_services)
    }

    /// Get application container status
    pub async fn get_app_status(app_id: &str) -> TappResult<AppStatus> {
        use serde::Deserialize;

        let app_dir = Self::get_app_dir(app_id);

        if !app_dir.exists() {
            let error = format!("App {} not found", app_id);
            error!(app_id = %app_id, error = %error, "App not found");
            return Err(TappError::InvalidParameter {
                field: "app_id".to_string(),
                reason: error,
            });
        }

        // Execute: docker compose ps --format json
        let output = Command::new("docker")
            .current_dir(&app_dir)
            .args(["compose", "ps", "--format", "json"])
            .output()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_compose_ps".to_string(),
                reason: format!("Failed to execute docker compose ps: {}", e),
            })?;

        let mut containers = Vec::new();
        let mut running = false;
        let mut started_at: Option<i64> = None;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            #[derive(Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct ContainerInfo {
                name: String,
                state: String,
                health: Option<String>,
                #[serde(default, deserialize_with = "deserialize_ports")]
                ports: Vec<serde_json::Value>,
            }

            // Custom deserializer for ports field that handles both string and array
            fn deserialize_ports<'de, D>(
                deserializer: D,
            ) -> Result<Vec<serde_json::Value>, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::{self, Visitor};
                use std::fmt;

                struct PortsVisitor;

                impl<'de> Visitor<'de> for PortsVisitor {
                    type Value = Vec<serde_json::Value>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("a string or an array")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        // If it's an empty string, return empty vec
                        if value.is_empty() {
                            return Ok(Vec::new());
                        }
                        // Try to parse as JSON array if it's a JSON string
                        serde_json::from_str(value).or_else(|_| Ok(Vec::new()))
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: de::SeqAccess<'de>,
                    {
                        let mut vec = Vec::new();
                        while let Some(item) = seq.next_element()? {
                            vec.push(item);
                        }
                        Ok(vec)
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(Vec::new())
                    }

                    fn visit_unit<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(Vec::new())
                    }
                }

                deserializer.deserialize_any(PortsVisitor)
            }

            // Parse each line as JSON (docker compose ps --format json outputs one JSON object per line)
            for line in stdout.lines() {
                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<ContainerInfo>(line) {
                    Ok(container) => {
                        if container.state == "running" {
                            running = true;
                        }

                        // Parse ports
                        let mut port_strings = Vec::new();
                        for port in &container.ports {
                            if let Some(port_str) = port.as_str() {
                                port_strings.push(port_str.to_string());
                            } else if let Some(port_obj) = port.as_object() {
                                // Format: "0.0.0.0:8080->80/tcp"
                                if let (
                                    Some(host_ip),
                                    Some(host_port),
                                    Some(container_port),
                                    Some(protocol),
                                ) = (
                                    port_obj.get("HostIP").and_then(|v| v.as_str()),
                                    port_obj.get("HostPort").and_then(|v| v.as_str()),
                                    port_obj.get("PrivatePort").and_then(|v| v.as_u64()),
                                    port_obj.get("Type").and_then(|v| v.as_str()),
                                ) {
                                    if !host_port.is_empty() {
                                        port_strings.push(format!(
                                            "{}:{}->{}/{}",
                                            host_ip, host_port, container_port, protocol
                                        ));
                                    } else {
                                        port_strings
                                            .push(format!("{}/{}", container_port, protocol));
                                    }
                                }
                            }
                        }

                        containers.push(ContainerStatus {
                            name: container.name,
                            state: container.state,
                            health: container.health,
                            ports: port_strings,
                        });
                    }
                    Err(e) => {
                        warn!(
                            line = %line,
                            error = %e,
                            "Failed to parse container info"
                        );
                    }
                }
            }

            // Try to get started_at from docker inspect
            if !containers.is_empty() {
                // Get the first container's start time as app start time
                if let Some(first_container) = containers.first() {
                    if let Ok(start_time) =
                        Self::get_container_start_time(&first_container.name).await
                    {
                        started_at = Some(start_time);
                    }
                }
            }
        }

        Ok(AppStatus {
            app_id: app_id.to_string(),
            running,
            container_count: containers.len(),
            containers,
            started_at,
        })
    }

    /// Get container start time
    async fn get_container_start_time(container_name: &str) -> TappResult<i64> {
        let output = Command::new("docker")
            .args(["inspect", "--format={{.State.StartedAt}}", container_name])
            .output()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_inspect_started_at".to_string(),
                reason: format!("Failed to inspect container: {}", e),
            })?;

        if !output.status.success() {
            return Err(DockerError::ContainerOperationFailed {
                operation: "docker_inspect_started_at".to_string(),
                reason: "Failed to get container start time".to_string(),
            }
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let time_str = stdout.trim();

        // Parse RFC3339 timestamp (e.g., "2024-01-01T12:00:00.123456789Z")
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(time_str) {
            Ok(dt.timestamp())
        } else {
            // Fallback: try parsing as Unix timestamp
            time_str.parse::<i64>().map_err(|_| {
                DockerError::ContainerOperationFailed {
                    operation: "parse_start_time".to_string(),
                    reason: format!("Failed to parse time: {}", time_str),
                }
                .into()
            })
        }
    }

    /// Start a specific service within an app
    pub async fn start_service(
        app_id: &str,
        service_name: &str,
        pull_image: bool,
    ) -> TappResult<()> {
        let app_dir = Self::get_app_dir(app_id);

        if !app_dir.exists() {
            return Err(TappError::InvalidParameter {
                field: "app_id".to_string(),
                reason: format!("App {} not found", app_id),
            });
        }

        // Check if service is already running
        let is_running = Self::is_service_running(app_id, service_name).await?;
        if is_running {
            warn!(
                app_id = %app_id,
                service_name = %service_name,
                "Service is already running"
            );
            return Err(TappError::InvalidParameter {
                field: "service_name".to_string(),
                reason: format!("Service {} is already running", service_name),
            });
        }

        info!(
            app_id = %app_id,
            service_name = %service_name,
            pull_image = pull_image,
            "🚀 Starting service"
        );

        // Build docker compose up command
        let mut args = vec!["compose", "up", "-d"];
        if pull_image {
            args.extend_from_slice(&["--pull", "always"]);
        }
        args.push(service_name);

        // Execute docker compose up -d [--pull always] <service_name> in app directory
        let output = tokio::process::Command::new("docker")
            .args(&args)
            .current_dir(&app_dir)
            .output()
            .await
            .map_err(|e| {
                TappError::Docker(DockerError::ContainerOperationFailed {
                    operation: "start_service".to_string(),
                    reason: format!("Failed to execute docker compose up: {}", e),
                })
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                app_id = %app_id,
                service_name = %service_name,
                stderr = %stderr,
                "❌ Docker compose up service failed"
            );
            return Err(TappError::Docker(DockerError::ContainerOperationFailed {
                operation: "start_service".to_string(),
                reason: format!("docker compose up {} failed: {}", service_name, stderr),
            }));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        info!(
            app_id = %app_id,
            service_name = %service_name,
            output = %stdout,
            "✅ Service started successfully"
        );

        Ok(())
    }

    /// Prune unused Docker images
    pub async fn prune_images(all: bool) -> TappResult<PruneImagesResult> {
        info!(all = all, "🧹 Pruning Docker images");

        // Build docker image prune command
        let mut args = vec!["system", "prune", "-f"];

        if all {
            args.push("--all");
        }

        // Note: docker image prune doesn't have --dry-run flag
        // We'll execute the command and parse the output
        info!(args = ?args, "Executing docker image prune");
        let output = Command::new("docker")
            .args(&args)
            .output()
            .await
            .map_err(|e| DockerError::ContainerOperationFailed {
                operation: "docker_image_prune".to_string(),
                reason: format!("Failed to execute docker image prune: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                stderr = %stderr,
                "❌ Docker image prune failed"
            );
            return Err(DockerError::ContainerOperationFailed {
                operation: "docker_image_prune".to_string(),
                reason: format!("docker image prune failed: {}", stderr),
            }
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output to extract information
        // Docker output format: "Deleted Images:\ndeleted: <id>\n...\nTotal reclaimed space: <size>"
        let mut images_deleted = 0i64;
        let mut space_reclaimed = 0i64;
        let mut deleted_images = Vec::new();

        // Count deleted images by counting "deleted:" lines
        for line in stdout.lines() {
            if line.trim().starts_with("deleted:") {
                images_deleted += 1;
                // Extract image ID (format: "deleted: sha256:...")
                if let Some(id) = line.trim().strip_prefix("deleted:") {
                    deleted_images.push(id.trim().to_string());
                }
            } else if line.contains("Total reclaimed space:") {
                // Extract space (format: "Total reclaimed space: 1.234GB" or "1.234MB")
                let space_str = line
                    .split("Total reclaimed space:")
                    .nth(1)
                    .and_then(|s| s.trim().split_whitespace().next())
                    .unwrap_or("0");

                // Parse size (handle GB, MB, KB, B)
                space_reclaimed = parse_size_to_bytes(space_str);
            }
        }

        info!(
            images_deleted = images_deleted,
            space_reclaimed = space_reclaimed,
            "Docker image prune completed successfully"
        );

        Ok(PruneImagesResult {
            images_deleted,
            space_reclaimed,
            deleted_images,
        })
    }
}

/// Result of docker image prune operation
#[derive(Debug, Clone)]
pub struct PruneImagesResult {
    pub images_deleted: i64,
    pub space_reclaimed: i64,
    pub deleted_images: Vec<String>,
}

/// Parse size string (e.g., "1.5GB", "500MB") to bytes
fn parse_size_to_bytes(size_str: &str) -> i64 {
    let size_str = size_str.trim().to_lowercase();

    // Extract number and unit
    let (num_str, unit) = if size_str.ends_with("gb") {
        (size_str.strip_suffix("gb").unwrap_or("0"), "gb")
    } else if size_str.ends_with("mb") {
        (size_str.strip_suffix("mb").unwrap_or("0"), "mb")
    } else if size_str.ends_with("kb") {
        (size_str.strip_suffix("kb").unwrap_or("0"), "kb")
    } else if size_str.ends_with("b") {
        (size_str.strip_suffix("b").unwrap_or("0"), "b")
    } else {
        (size_str.as_str(), "")
    };

    let num: f64 = num_str.parse().unwrap_or(0.0);

    match unit {
        "gb" => (num * 1024.0 * 1024.0 * 1024.0) as i64,
        "mb" => (num * 1024.0 * 1024.0) as i64,
        "kb" => (num * 1024.0) as i64,
        "b" | "" => num as i64,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_mount_file(source_path: &str, content: &[u8]) -> MountFile {
        MountFile {
            source_path: source_path.to_string(),
            content: content.to_vec(),
            mode: "0644".to_string(),
        }
    }

    #[tokio::test]
    async fn test_store_mount_files_preserves_directory_structure() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let files = vec![
            make_mount_file("./subdir/file.txt", b"hello"),
            make_mount_file("./flat.txt", b"world"),
        ];

        let mapping = DockerComposeManager::store_mount_files(&base, &files)
            .await
            .unwrap();

        // Subdirectory structure must be preserved (not flattened to subdir_file.txt)
        let subdir_host = base.join("subdir/file.txt");
        assert!(
            subdir_host.exists(),
            "expected file at subdir/file.txt, not flattened"
        );
        assert_eq!(std::fs::read(&subdir_host).unwrap(), b"hello");

        let flat_host = base.join("flat.txt");
        assert!(flat_host.exists());
        assert_eq!(std::fs::read(&flat_host).unwrap(), b"world");

        // Mapping keys are the original source paths
        assert!(mapping.contains_key("./subdir/file.txt"));
        assert!(mapping.contains_key("./flat.txt"));
    }

    #[tokio::test]
    async fn test_store_mount_files_blocks_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();

        let files = vec![make_mount_file("../escape.txt", b"evil")];

        let mapping = DockerComposeManager::store_mount_files(&base, &files)
            .await
            .unwrap();

        // Path traversal must be rejected — nothing written outside base
        assert!(mapping.is_empty(), "traversal path should be skipped");
        assert!(!tmp.path().parent().unwrap().join("escape.txt").exists());
    }
}
