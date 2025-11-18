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
    fn validate_api_key(&self, req: &Request<()>) -> Result<(), Status> {
        // If API key auth is not configured or disabled, allow all requests
        let Some(config) = self.config.as_ref() else {
            return Ok(());
        };

        if !config.enabled {
            return Ok(());
        }

        // Extract method name from request URI
        let uri = req.uri();
        let method_name = uri
            .path()
            .split('/')
            .last()
            .unwrap_or("")
            .to_string();

        debug!(
            method = %method_name,
            uri = %uri,
            "Processing API key authentication"
        );

        // Check if this method requires authentication
        // If protected_methods is empty, all methods require auth
        // If protected_methods is specified, only those methods require auth
        let requires_auth = if config.protected_methods.is_empty() {
            true
        } else {
            config.protected_methods.contains(&method_name)
        };

        if !requires_auth {
            debug!(
                method = %method_name,
                "Method does not require API key authentication"
            );
            return Ok(());
        }

        // Extract API key from metadata
        // The client should send: metadata.insert("x-api-key", api_key)
        let metadata = req.metadata();
        let api_key = metadata
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                warn!(
                    method = %method_name,
                    remote_addr = ?req.remote_addr(),
                    event = "AUTH_MISSING_API_KEY",
                    "API key missing in request metadata"
                );
                Status::unauthenticated("Missing API key. Please provide 'x-api-key' in metadata")
            })?;

        // Validate API key
        if !config.keys.contains(&api_key.to_string()) {
            warn!(
                method = %method_name,
                remote_addr = ?req.remote_addr(),
                event = "AUTH_INVALID_API_KEY",
                "Invalid API key attempted"
            );
            return Err(Status::permission_denied("Invalid API key"));
        }

        debug!(
            method = %method_name,
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

        // Validate API key
        self.validate_api_key(&temp_req)?;

        // Reconstruct the original request
        Ok(Request::from_parts(metadata, extensions, msg))
    }
}
