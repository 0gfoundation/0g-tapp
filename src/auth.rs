use crate::config::ApiKeyConfig;
use std::sync::Arc;
use tonic::{Request, Status};
use tracing::{debug, warn};

/// API Key authentication interceptor for gRPC
#[derive(Clone)]
pub struct ApiKeyInterceptor {
    config: Arc<Option<ApiKeyConfig>>,
}

impl ApiKeyInterceptor {
    /// Create a new API key interceptor with the given configuration
    pub fn new(config: Option<ApiKeyConfig>) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Validate API key from request metadata
    /// Note: Method-level filtering should be done at the service implementation level
    /// This interceptor validates all requests if enabled
    fn validate_api_key(&self, req: &Request<()>) -> Result<(), Status> {
        // If API key auth is not configured or disabled, allow all requests
        let Some(config) = self.config.as_ref() else {
            return Ok(());
        };

        if !config.enabled {
            return Ok(());
        }

        debug!("Processing API key authentication");

        // Extract API key from metadata
        // The client should send: metadata.insert("x-api-key", api_key)
        let metadata = req.metadata();
        let api_key = metadata
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                warn!(
                    remote_addr = ?req.remote_addr(),
                    event = "AUTH_MISSING_API_KEY",
                    "API key missing in request metadata"
                );
                Status::unauthenticated("Missing API key. Please provide 'x-api-key' in metadata")
            })?;

        // Validate API key
        if !config.keys.contains(&api_key.to_string()) {
            warn!(
                remote_addr = ?req.remote_addr(),
                event = "AUTH_INVALID_API_KEY",
                "Invalid API key attempted"
            );
            return Err(Status::permission_denied("Invalid API key"));
        }

        debug!(
            event = "AUTH_SUCCESS",
            "API key validation successful"
        );

        Ok(())
    }

    /// Intercept the request and validate API key
    pub fn intercept<T>(&self, req: Request<T>) -> Result<Request<T>, Status> {
        // Create a temporary request with unit type to validate metadata
        let (metadata, extensions, msg) = req.into_parts();
        let temp_req = Request::from_parts(metadata.clone(), extensions.clone(), ());

        // Validate API key (applies to all methods when enabled)
        self.validate_api_key(&temp_req)?;

        // Reconstruct the original request
        Ok(Request::from_parts(metadata, extensions, msg))
    }
}

/// Helper function for validating API key at method level
/// Use this in individual RPC handlers for fine-grained control
pub fn validate_method_api_key(
    config: &Option<ApiKeyConfig>,
    metadata: &tonic::metadata::MetadataMap,
    method_name: &str,
) -> Result<(), Status> {
    let Some(api_config) = config else {
        return Ok(());
    };

    if !api_config.enabled {
        return Ok(());
    }

    // Check if this method requires authentication
    let requires_auth = if api_config.protected_methods.is_empty() {
        // If no methods specified, all methods require auth (handled by interceptor)
        return Ok(());
    } else {
        api_config.protected_methods.iter().any(|m| m == method_name)
    };

    if !requires_auth {
        return Ok(());
    }

    // Extract and validate API key
    let api_key = metadata
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Status::unauthenticated("Missing API key. Please provide 'x-api-key' in metadata")
        })?;

    if !api_config.keys.contains(&api_key.to_string()) {
        return Err(Status::permission_denied("Invalid API key"));
    }

    Ok(())
}
