use crate::error::{ConfigError, TappResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Default)]
pub struct EvidenceServiceConfig {
    /// Path to the evidence service configuration file
    #[serde(default = "default_evidence_config_path")]
    pub config_path: Option<String>,
}

/// Docker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootServiceConfig {
    /// Attestation agent configuration
    #[serde(default)]
    pub aa_config_path: Option<String>,

    /// Docker socket path
    #[serde(default = "default_docker_socket")]
    pub socket_path: String,

    /// Container startup timeout in seconds
    #[serde(default = "default_container_timeout")]
    pub container_timeout_seconds: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (json or pretty)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path (if None, logs to stdout)
    pub file_path: Option<PathBuf>,

    /// Maximum log file size in MB
    #[serde(default = "default_max_log_size")]
    pub max_file_size_mb: u64,

    /// Maximum number of log files to keep
    #[serde(default = "default_max_log_files")]
    pub max_files: usize,
}

/// Main configuration structure for TAPP service
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TappConfig {
    pub logging: LoggingConfig,
    pub boot: BootServiceConfig,
    pub server: ServerConfig,
    pub kbs: Option<KbsConfig>,
}

impl TappConfig {
    pub fn load(config_path: String) -> TappResult<Self> {
        toml::from_str(&std::fs::read_to_string(&config_path).map_err(|_| {
            ConfigError::FileNotFound {
                path: config_path.clone(),
            }
        })?)
        .map_err(|e| {
            ConfigError::ParseFailed {
                reason: e.to_string(),
            }
            .into()
        })
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address for gRPC server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,

    /// Enable TLS
    #[serde(default)]
    pub tls_enabled: bool,

    /// TLS certificate path (if TLS enabled)
    pub tls_cert_path: Option<PathBuf>,

    /// TLS private key path (if TLS enabled)
    pub tls_key_path: Option<PathBuf>,
}

/// KBS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsConfig {
    /// KBS endpoint URL
    pub endpoint: String,

    /// Connection timeout in seconds
    #[serde(default = "default_kbs_timeout")]
    pub timeout_seconds: u64,

    /// KBS certificate path (for custom CA)
    pub cert_path: Option<PathBuf>,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,

    /// Default app key types to support
    #[serde(default = "default_supported_key_types")]
    pub supported_key_types: Vec<String>,
}

/// Retry configuration for KBS operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,

    /// Initial retry delay in milliseconds
    #[serde(default = "default_initial_delay")]
    pub initial_delay_ms: u64,

    /// Maximum retry delay in milliseconds
    #[serde(default = "default_max_delay")]
    pub max_delay_ms: u64,
}

// Default value functions
fn default_bind_address() -> String {
    "0.0.0.0:50051".to_string()
}

fn default_max_connections() -> usize {
    1000
}

fn default_request_timeout() -> u64 {
    30
}

fn default_kbs_timeout() -> u64 {
    30
}

fn default_supported_key_types() -> Vec<String> {
    vec!["ethereum".to_string(), "rsa".to_string(), "ec".to_string()]
}

fn default_max_retries() -> usize {
    3
}

fn default_initial_delay() -> u64 {
    1000
}

fn default_max_delay() -> u64 {
    30000
}

fn default_docker_socket() -> String {
    "/var/run/docker.sock".to_string()
}

fn default_container_timeout() -> u64 {
    300
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_max_log_size() -> u64 {
    100
}

fn default_max_log_files() -> usize {
    10
}

fn default_kbs_endpoint() -> String {
    "http://localhost:8080".to_string()
}

impl Default for KbsConfig {
    fn default() -> Self {
        Self {
            endpoint: default_kbs_endpoint(),
            timeout_seconds: default_kbs_timeout(),
            cert_path: None,
            retry: RetryConfig::default(),
            supported_key_types: default_supported_key_types(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            max_connections: default_max_connections(),
            request_timeout_seconds: default_request_timeout(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_delay_ms: default_initial_delay(),
            max_delay_ms: default_max_delay(),
        }
    }
}

impl Default for BootServiceConfig {
    fn default() -> Self {
        Self {
            aa_config_path: Some("config/attestation-agent.toml".to_string()),
            socket_path: default_docker_socket(),
            container_timeout_seconds: default_container_timeout(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file_path: None,
            max_file_size_mb: default_max_log_size(),
            max_files: default_max_log_files(),
        }
    }
}

impl TappConfig {}
