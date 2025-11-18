use crate::config::ApiKeyConfig;
use std::task::{Context, Poll};
use tonic::body::BoxBody;
use tonic::{Code, Status};
use tower::{Layer, Service};
use tracing::{debug, warn};

/// Tower Layer for API key authentication
/// This wraps the entire gRPC service and can access method paths
#[derive(Clone)]
pub struct ApiKeyLayer {
    config: Option<ApiKeyConfig>,
}

impl ApiKeyLayer {
    pub fn new(config: Option<ApiKeyConfig>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for ApiKeyLayer {
    type Service = ApiKeyMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        ApiKeyMiddleware {
            inner: service,
            config: self.config.clone(),
        }
    }
}

/// Middleware that performs API key validation
#[derive(Clone)]
pub struct ApiKeyMiddleware<S> {
    inner: S,
    config: Option<ApiKeyConfig>,
}

impl<S> Service<http::Request<BoxBody>> for ApiKeyMiddleware<S>
where
    S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>, Error = std::convert::Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();

        Box::pin(async move {
            // Extract method name from URI path
            // gRPC method path format: /package.Service/Method
            let path = req.uri().path();
            let method_name = path.split('/').last().unwrap_or("Unknown");

            debug!(method = %method_name, path = %path, "API key validation");

            // Validate API key if configured
            if let Err(status) = validate_request(&config, &req, method_name) {
                // Convert Status to HTTP response
                let (mut parts, _body) = req.into_parts();
                let response = status.to_http();
                return Ok(response);
            }

            // Call the inner service
            inner.call(req).await
        })
    }
}

/// Validate the request based on API key configuration
fn validate_request(
    config: &Option<ApiKeyConfig>,
    req: &http::Request<BoxBody>,
    method_name: &str,
) -> Result<(), Status> {
    // If API key auth is not configured or disabled, allow all requests
    let Some(api_config) = config else {
        return Ok(());
    };

    if !api_config.enabled {
        return Ok(());
    }

    // Check if this method requires authentication
    let requires_auth = if api_config.protected_methods.is_empty() {
        // If empty, all methods require auth
        true
    } else {
        // Check if current method is in the protected list
        api_config
            .protected_methods
            .iter()
            .any(|m| m == method_name)
    };

    if !requires_auth {
        debug!(method = %method_name, "Method does not require API key");
        return Ok(());
    }

    // Extract API key from headers (gRPC metadata becomes HTTP headers)
    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!(
                method = %method_name,
                event = "AUTH_MISSING_API_KEY",
                "API key missing in request"
            );
            Status::unauthenticated("Missing API key. Please provide 'x-api-key' in metadata")
        })?;

    // Validate API key
    if !api_config.keys.contains(&api_key.to_string()) {
        warn!(
            method = %method_name,
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
