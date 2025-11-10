use thiserror::Error;

/// Result type for TAPP operations
pub type TappResult<T> = Result<T, TappError>;

/// Main error type for TAPP service
#[derive(Error, Debug)]
pub enum TappError {
    /// Attestation related errors
    #[error("Attestation error: {0}")]
    Attestation(#[from] AttestationError),

    /// KBS related errors
    #[error("KBS error: {0}")]
    Kbs(#[from] KbsError),

    /// Docker related errors
    #[error("Docker error: {0}")]
    Docker(#[from] DockerError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// gRPC errors
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Cryptographic errors
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Invalid parameter errors
    #[error("Invalid parameter: {field} - {reason}")]
    InvalidParameter { field: String, reason: String },

    /// Service unavailable
    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String },

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Attestation specific errors
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("TEE not detected or unsupported")]
    TeeNotSupported,

    #[error("Evidence generation failed: {reason}")]
    EvidenceGenerationFailed { reason: String },

    #[error("Invalid runtime data: {reason}")]
    InvalidRuntimeData { reason: String },

    #[error("Unsupported evidence format: {format}")]
    UnsupportedEvidenceFormat { format: String },

    #[error("RTMR extension failed: {reason}")]
    RtmrExtensionFailed { reason: String },
}

/// KBS specific errors
#[derive(Error, Debug)]
pub enum KbsError {
    #[error("KBS connection failed: {endpoint}")]
    ConnectionFailed { endpoint: String },

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Resource not found: {resource_uri}")]
    ResourceNotFound { resource_uri: String },

    #[error("Invalid resource URI: {uri}")]
    InvalidResourceUri { uri: String },

    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },

    #[error("Unsupported key type: {key_type}")]
    UnsupportedKeyType { key_type: String },
}

/// Docker specific errors
#[derive(Error, Debug)]
pub enum DockerError {
    #[error("Docker daemon connection failed")]
    ConnectionFailed,

    #[error("Invalid compose content: {reason}")]
    InvalidComposeContent { reason: String },

    #[error("Container operation failed: {operation} - {reason}")]
    ContainerOperationFailed { operation: String, reason: String },

    #[error("Volume measurement failed: {path}")]
    VolumeMeasurementFailed { path: String },

    #[error("Service not found: {service_name}")]
    ServiceNotFound { service_name: String },
}

/// Configuration specific errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing required configuration: {field}")]
    MissingField { field: String },

    #[error("Invalid configuration value: {field} - {reason}")]
    InvalidValue { field: String, reason: String },

    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },

    #[error("Configuration parsing failed: {reason}")]
    ParseFailed { reason: String },
}

// Implement conversion from guest-components errors
impl From<anyhow::Error> for TappError {
    fn from(err: anyhow::Error) -> Self {
        TappError::Internal(err.to_string())
    }
}

// Convert to gRPC Status for network responses
impl From<TappError> for tonic::Status {
    fn from(err: TappError) -> Self {
        use tonic::Status;

        match err {
            TappError::InvalidParameter { field, reason } => {
                Status::invalid_argument(format!("Invalid {}: {}", field, reason))
            }
            TappError::ServiceUnavailable { service } => {
                Status::unavailable(format!("Service {} is unavailable", service))
            }
            TappError::Attestation(AttestationError::TeeNotSupported) => {
                Status::failed_precondition("TEE not supported on this platform")
            }
            TappError::Kbs(KbsError::AuthenticationFailed) => {
                Status::unauthenticated("KBS authentication failed")
            }
            TappError::Kbs(KbsError::ResourceNotFound { resource_uri }) => {
                Status::not_found(format!("Resource not found: {}", resource_uri))
            }
            TappError::Docker(DockerError::ServiceNotFound { service_name }) => {
                Status::not_found(format!("Service not found: {}", service_name))
            }
            TappError::Config(_) => Status::failed_precondition("Service configuration error"),
            _ => Status::internal(err.to_string()),
        }
    }
}

// Helper macros for error creation
#[macro_export]
macro_rules! invalid_param {
    ($field:expr, $reason:expr) => {
        TappError::InvalidParameter {
            field: $field.to_string(),
            reason: $reason.to_string(),
        }
    };
}

#[macro_export]
macro_rules! service_unavailable {
    ($service:expr) => {
        TappError::ServiceUnavailable {
            service: $service.to_string(),
        }
    };
}

#[macro_export]
macro_rules! internal_error {
    ($msg:expr) => {
        TappError::Internal($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        TappError::Internal(format!($fmt, $($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion_to_grpc() {
        let err = TappError::InvalidParameter {
            field: "app_id".to_string(),
            reason: "cannot be empty".to_string(),
        };
        let status: tonic::Status = err.into();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_error_macros() {
        let err = invalid_param!("test_field", "test reason");
        match err {
            TappError::InvalidParameter { field, reason } => {
                assert_eq!(field, "test_field");
                assert_eq!(reason, "test reason");
            }
            _ => panic!("Wrong error type"),
        }
    }
}
