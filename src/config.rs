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

    /// Maximum number of rotated (daily) log files to keep; oldest are deleted.
    /// Bounds total log growth — without a cap, daily rotation still grows
    /// unbounded and can exhaust the RAM rootfs on CVM images (issue #23).
    #[serde(default = "default_max_log_files")]
    pub max_log_files: usize,
}

/// Main configuration structure for TAPP service
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TappConfig {
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub boot: BootServiceConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub kbs: Option<KbsConfig>,
    #[serde(default)]
    pub chain: Option<ChainConfig>,
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
    /// Bind address for gRPC server (used when unix_socket_path is not set)
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Unix socket path for gRPC server. When set, the server listens on this
    /// Unix domain socket IN ADDITION TO the TCP `bind_address` (not instead of it),
    /// so remote clients keep using TCP while same-host clients can use the socket.
    /// This is the recommended path for local key retrieval — a Docker container
    /// mounts the socket file instead of using `extra_hosts:
    /// host.docker.internal:host-gateway`.
    ///
    /// Example: "/run/tapp/tapp.sock"
    #[serde(default)]
    pub unix_socket_path: Option<PathBuf>,

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

    /// Permission configuration for signature-based authentication
    #[serde(default)]
    pub permission: Option<PermissionConfig>,
}

/// Permission-based authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionConfig {
    /// Enable permission-based authentication
    #[serde(default)]
    pub enabled: bool,

    /// Tapp owner EVM address (has full control).
    /// Example: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    ///
    /// OPTIONAL since 0.3: when absent, the tapp boots UNCLAIMED — the first
    /// valid signer of the ClaimConfig RPC becomes the owner, and the claim is
    /// extended into the runtime measurement. This keeps the CVM image (and
    /// its golden reference values) owner-independent. Setting it here is the
    /// legacy baked-in mode and still works.
    #[serde(default)]
    pub owner_address: Option<String>,

    /// Where the claimed owner is persisted so a tapp-server restart within
    /// the same boot cannot reopen the claim. tmpfs by design: cleared on VM
    /// reboot, matching the RTMR lifetime (reboot = re-claim, re-measured).
    #[serde(default = "default_owner_state_path")]
    pub owner_state_path: PathBuf,
}

/// On-chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Ethereum-compatible RPC URL
    pub rpc_url: String,
    /// TappRegistry contract address
    pub contract_address: String,
}

/// KBS configuration — points to the KMS cluster for app secret retrieval.
/// in-memory key generation is always active regardless of this config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbsConfig {
    /// KMS cluster node URLs (tried in order, first success wins)
    pub node_urls: Vec<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_kbs_timeout")]
    pub timeout_seconds: u64,

    /// KBS certificate path (for custom CA)
    pub cert_path: Option<PathBuf>,

    /// Retry configuration
    #[serde(default = "default_kbs_retry")]
    pub retry: RetryConfig,
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

fn default_kbs_retry() -> RetryConfig {
    RetryConfig {
        max_retries: 2,
        initial_delay_ms: 200,
        max_delay_ms: 2000,
    }
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

fn default_max_log_files() -> usize {
    7
}

fn default_owner_state_path() -> PathBuf {
    PathBuf::from("/run/tapp/claimed_owner")
}

impl Default for KbsConfig {
    fn default() -> Self {
        Self {
            node_urls: vec![],
            timeout_seconds: default_kbs_timeout(),
            cert_path: None,
            retry: RetryConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            unix_socket_path: None,
            max_connections: default_max_connections(),
            request_timeout_seconds: default_request_timeout(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            permission: None,
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
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file_path: None,
            max_log_files: default_max_log_files(),
        }
    }
}

impl TappConfig {}
