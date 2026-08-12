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

/// Where an app's TLS private key comes from. The two are not better and worse — they
/// trade the same thing in opposite directions.
///
/// **`Local`** derives it from the app's own signer, which is generated inside this CVM and
/// never leaves it. The key is therefore bound to *this instance*: a verifier that compares
/// it against `report_data` learns "the endpoint I am talking to is this TEE", the strongest
/// statement available. Nothing external is involved — no KMS, no on-chain registration — so
/// it works from first boot. The cost is that the signer is regenerated on every restart, so
/// the key changes with it: certificate pinning breaks, Certificate Transparency monitoring
/// sees churn instead of signal, and an ACME certificate would need reissuing every restart
/// against a rate limit.
///
/// **`Kms`** derives it from `(app_id, material)` at the KMS cluster, so it is stable across
/// restarts and identical on every node of the app. That is what makes pinning, transparency
/// monitoring and normal certificate renewal work. The cost is that the key exists outside
/// this CVM — the answering KMS node reconstructs it — and any registered signer of the app
/// can obtain it, so the statement weakens to "some TEE of this app". It also needs the app
/// registered on chain and the cluster reachable.
///
/// Local is the default because it always works and asks nothing of the deployer; stability
/// is the thing you opt into once something needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsKeySource {
    #[default]
    Local,
    Kms,
}

impl TlsKeySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsKeySource::Local => "local",
            TlsKeySource::Kms => "kms",
        }
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

    /// Permission bits on the socket, as an octal string like `"0660"`.
    ///
    /// `0600` — the original value — meant only root could open it, so every application
    /// that fetches key material had to run its container as root. That is a poor trade:
    /// an image that drops privileges is giving up real hardening to satisfy a file mode,
    /// and it does not buy anything, because the socket's protection was never the file
    /// mode. Anything the socket is bind-mounted into can read every app's key material,
    /// so **the mount is the boundary** and the mode only decides who on the host may also
    /// reach it.
    ///
    /// `0660` is the default: a container keeps a non-root uid and adds the socket's group
    /// with `group_add`, which is exactly the hardening the old value forced people to
    /// abandon. `0666` opens it to every user on the host and is a deliberate choice, not
    /// a default.
    #[serde(default = "default_socket_mode")]
    pub unix_socket_mode: String,

    /// Group that owns the socket. Unset leaves it root-owned, which pairs with
    /// `group_add: ["0"]` on the container — a non-root user in the root *group*.
    ///
    /// Set it to a dedicated gid when a node runs containers that should not share a group
    /// with anything else on the host; the containers then use that gid instead.
    #[serde(default)]
    pub unix_socket_gid: Option<u32>,

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

    /// Where an app's TLS private key comes from. See [`TlsKeySource`].
    #[serde(default)]
    pub tls_key_source: TlsKeySource,

    /// Certificate authority for app TLS certificates, e.g. `http://ca:8080`.
    ///
    /// Optional on purpose. Unset, `GetAppTlsCert` self-signs, which is enough for any
    /// client that checks the public key against the attestation — the issuer is
    /// irrelevant to that check. A CA is what makes the same certificate acceptable to
    /// clients that will not do it, such as browsers driving off a trust store.
    pub ca_url: Option<String>,

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
/// 0660, not 0600: see `unix_socket_mode`. A string because TOML has no octal literal,
/// and `0600` written as a TOML integer is six hundred.
fn default_socket_mode() -> String {
    "0660".to_string()
}

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
            unix_socket_mode: default_socket_mode(),
            unix_socket_gid: None,
            unix_socket_path: None,
            max_connections: default_max_connections(),
            request_timeout_seconds: default_request_timeout(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_key_source: TlsKeySource::default(),
            ca_url: None,
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

#[cfg(test)]
mod socket_mode {
    use super::*;

    /// The parse main.rs performs, kept here so the config that documents it also tests it.
    fn parse(mode: &str) -> Result<u32, ()> {
        u32::from_str_radix(mode.trim_start_matches("0o"), 8).map_err(|_| ())
    }

    #[test]
    fn the_default_lets_a_non_root_container_in_via_its_group() {
        // The whole point of the change: 0600 admitted only root, so every consumer had to
        // run as root. 0660 admits a process whose group matches, which a container gets
        // with group_add while keeping a non-root user.
        assert_eq!(parse(&default_socket_mode()).unwrap(), 0o660);
    }

    #[test]
    fn a_mode_is_read_as_octal_not_decimal() {
        // "0660" read as decimal is 660, which is 0o1224 — group-writable, world-nothing,
        // and with a stray setgid-adjacent bit. It would half-work, which is worse than
        // failing, so the radix is not incidental.
        assert_eq!(parse("0660").unwrap(), 0o660);
        assert_eq!(parse("0600").unwrap(), 0o600);
        assert_eq!(parse("0666").unwrap(), 0o666);
        assert_ne!(parse("0660").unwrap(), 660);
    }

    #[test]
    fn the_rust_style_prefix_is_accepted_too() {
        assert_eq!(parse("0o660").unwrap(), 0o660);
    }

    #[test]
    fn a_mode_that_is_not_octal_is_refused_rather_than_guessed() {
        // Refusing beats defaulting: a typo that silently became 0600 would reintroduce
        // the very problem this setting exists to fix, and nothing would say so.
        for bad in ["rw-rw----", "0o", "", "0899", "abc"] {
            assert!(parse(bad).is_err(), "accepted {:?}", bad);
        }
    }
}
