use crate::config::PermissionConfig;
use crate::permission::{Permission, PermissionManager};
use crate::signature_auth::{build_sign_message, recover_evm_address, verify_timestamp};
use std::sync::Arc;
use std::task::{Context, Poll};
use tonic::body::BoxBody;
use tonic::Status;
use tower::{Layer, Service};
use tracing::{debug, info, warn};

/// Tower Layer for signature-based authentication
/// This wraps the entire gRPC service and validates EVM signatures
#[derive(Clone)]
pub struct AuthLayer {
    permission_manager: Option<Arc<PermissionManager>>,
    enabled: bool,
}

impl AuthLayer {
    pub fn new(config: Option<PermissionConfig>) -> Self {
        let (permission_manager, enabled) = if let Some(cfg) = config {
            if cfg.enabled {
                let pm = PermissionManager::new(cfg.owner_address.clone());
                (Some(Arc::new(pm)), true)
            } else {
                (None, false)
            }
        } else {
            (None, false)
        };
        // NOTE: main.rs always uses with_permission_manager; this path only
        // serves tests and keeps the claim/persistence wiring out of the layer.

        Self {
            permission_manager,
            enabled,
        }
    }

    pub fn with_permission_manager(permission_manager: Arc<PermissionManager>) -> Self {
        Self {
            permission_manager: Some(permission_manager),
            enabled: true,
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthMiddleware {
            inner: service,
            permission_manager: self.permission_manager.clone(),
            enabled: self.enabled,
        }
    }
}

/// Middleware that performs signature validation and permission checks
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    permission_manager: Option<Arc<PermissionManager>>,
    enabled: bool,
}

impl<S> Service<http::Request<BoxBody>> for AuthMiddleware<S>
where
    S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<BoxBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let permission_manager = self.permission_manager.clone();
        let enabled = self.enabled;

        Box::pin(async move {
            // Extract method name from URI path
            // gRPC method path format: /package.Service/Method
            let path = req.uri().path();
            let method_name = path.split('/').last().unwrap_or("Unknown").to_string();

            debug!(
                method = %method_name,
                path = %path,
                "Processing authentication"
            );

            // If auth is not enabled, allow all requests
            if !enabled || permission_manager.is_none() {
                debug!("Authentication disabled, allowing request");
                return inner.call(req).await;
            }

            let pm = permission_manager.as_ref().unwrap();

            // Check if method requires authentication
            let method_permission = get_method_permission(&method_name);

            // Public methods don't require authentication
            if method_permission == MethodPermission::Public {
                debug!(method = %method_name, "Public method, no auth required");
                return inner.call(req).await;
            }

            // Socket-only methods: no signature, but the request must have arrived on the
            // Unix socket. tonic records connect-info per listener, and a TCP connection
            // always carries a peer address while a Unix one never does — so this is the
            // transport itself answering, not a judgement about the address.
            if method_permission == MethodPermission::LocalOnly {
                let over_tcp = req
                    .extensions()
                    .get::<tonic::transport::server::TcpConnectInfo>()
                    .and_then(|i| i.remote_addr())
                    .is_some();
                if over_tcp {
                    warn!(
                        method = %method_name,
                        event = "AUTH_NOT_LOCAL",
                        "Refused: this method hands over key material and is served only on \
                         the Unix socket"
                    );
                    let response = Status::permission_denied(format!(
                        "{} is served only on the tapp Unix socket; mount it into the \
                         container instead of connecting over TCP",
                        method_name
                    ))
                    .into_http();
                    return Ok(response);
                }
                debug!(method = %method_name, "Local socket method, no auth required");
                return inner.call(req).await;
            }

            // Extract headers needed for validation
            let signature = req
                .headers()
                .get("x-signature")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let timestamp_str = req
                .headers()
                .get("x-timestamp")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Validate signature
            let signer_address = match validate_signature(signature, timestamp_str, &method_name) {
                Ok(addr) => addr,
                Err(status) => {
                    let response = status.into_http();
                    return Ok(response);
                }
            };

            // Get user permission level
            let user_permission = pm.get_permission(&signer_address).await;

            debug!(
                method = %method_name,
                signer = %signer_address,
                permission = ?user_permission,
                "User permission determined"
            );

            // Check if user has required permission for this method
            if !is_authorized(&method_permission, &user_permission) {
                warn!(
                    method = %method_name,
                    signer = %signer_address,
                    required = ?method_permission,
                    actual = ?user_permission,
                    event = "AUTH_INSUFFICIENT_PERMISSION",
                    "Insufficient permission"
                );
                let response =
                    Status::permission_denied("Insufficient permission for this operation")
                        .into_http();
                return Ok(response);
            }

            info!(
                method = %method_name,
                signer = %signer_address,
                permission = ?user_permission,
                event = "AUTH_SUCCESS",
                "Authentication and authorization successful"
            );

            // Inject signer address into request extensions for business layer
            req.extensions_mut()
                .insert(SignerAddress(signer_address.clone()));

            // Call the inner service
            inner.call(req).await
        })
    }
}

/// Extract signer address from request extensions
pub fn get_signer_address<T>(req: &tonic::Request<T>) -> Option<String> {
    req.extensions().get::<SignerAddress>().map(|s| s.0.clone())
}

/// Wrapper type for signer address stored in request extensions
#[derive(Clone, Debug)]
pub struct SignerAddress(pub String);

// ============================================================================
// Permission and authorization logic
// ============================================================================

/// Method permission requirements
#[derive(Debug, Clone, PartialEq, Eq)]
enum MethodPermission {
    Public,        // No auth required
    /// Reachable only over the Unix socket, never over TCP. No signature either — the
    /// caller is a container inside this CVM asking for key material, and it has no key
    /// to sign with; it is calling in order to obtain one.
    ///
    /// The socket is the control, and it is a precise one: `main.rs` creates it 0600
    /// inside a 0700 directory, so reaching it means holding a file descriptor the
    /// filesystem granted. The check it replaces asked whether the source IP was private
    /// — which is true of every machine in the same VPC, not just this one.
    LocalOnly,
    Authenticated, // Any valid signature (permission decided in the handler)
    OwnerOnly,     // Only tapp owner
    Whitelist,     // Owner or whitelisted users
}

/// Get permission requirement for a method.
///
/// An unclassified method gets OwnerOnly, which fails closed — a new RPC is unreachable
/// until someone decides what guards it, rather than quietly inheriting the weakest rule.
fn get_method_permission(method_name: &str) -> MethodPermission {
    classify(method_name).unwrap_or_else(|| {
        warn!(method = %method_name, "Unknown method, defaulting to OwnerOnly");
        MethodPermission::OwnerOnly
    })
}

/// `None` means the method is not listed here. Split out from the fallback so a test can
/// tell "explicitly OwnerOnly" from "nobody decided", which the return type alone cannot.
fn classify(method_name: &str) -> Option<MethodPermission> {
    Some(match method_name {
        // Nothing to protect — the answer is public either way.
        "GetEvidence" | "GetAppKey" | "GetAppInfo" | "ListApps" | "GetTaskStatus"
        | "GetServiceStatus" | "GetTappInfo" => MethodPermission::Public,

        // Hand over key material. Socket only.
        "GetAppSecretKey" | "GetSecretResource" | "GetAppTlsCert" => {
            MethodPermission::LocalOnly
        }

        // Signature required, but no permission level: while the tapp is
        // unclaimed anybody may claim (first-come-first-served); once claimed
        // the handler rejects with ALREADY_EXISTS.
        "ClaimConfig" => MethodPermission::Authenticated,

        // Owner-only methods
        "StartApp"
        | "StopApp"
        // Whoever can change this decides which verifier the node believes, and hence
        // which KMS key it will accept. Owner authority is the right level — the owner
        // can already start arbitrary apps — but it must not be reachable unsigned.
        | "UpdateTrustAnchors"
        | "AddToWhitelist"
        | "RemoveFromWhitelist"
        | "ListWhitelist"
        | "ListAllOwnerships"
        | "StopService"
        | "StartService"
        // These two were never listed and reached OwnerOnly through the fallback. Stated
        // explicitly to keep the behaviour they already had — ListAppMeasurements is a
        // deprecated stub that errors either way, and tapp-cli already signs for
        // GetAppContainerStatus.
        | "ListAppMeasurements"
        | "GetAppContainerStatus" => MethodPermission::OwnerOnly,

        // Owner or whitelist methods
        "GetServiceLogs" | "GetAppLogs" | "GetAppOwnership" | "WithdrawBalance" | "DockerLogin"
        | "DockerLogout" | "PruneImages" => MethodPermission::Whitelist,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every RPC the service declares must be classified on purpose.
    ///
    /// The fallback is OwnerOnly, so forgetting one does not open a hole — it makes the
    /// RPC unusable by the callers that need it, which is how GetAppTlsCert first failed:
    /// an app container has no key to sign with, so it got "Missing signature" from a rule
    /// nobody had chosen. Reading the method list out of the proto rather than repeating it
    /// here is the point; a list maintained by hand would drift the same way.
    #[test]
    fn every_rpc_in_the_proto_has_a_deliberate_permission() {
        let proto = include_str!("../proto/tapp_service.proto");
        let mut unclassified = Vec::new();
        let mut seen = 0usize;
        for line in proto.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("rpc ") else {
                continue;
            };
            let name = rest.split('(').next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            seen += 1;
            if classify(name).is_none() {
                unclassified.push(name.to_string());
            }
        }
        assert!(seen > 20, "parsed only {} rpcs — the proto layout changed", seen);
        assert!(
            unclassified.is_empty(),
            "these RPCs fall through to the OwnerOnly default; classify them in \
             get_method_permission: {:?}",
            unclassified
        );
    }
}

/// Check if user has required permission
fn is_authorized(required: &MethodPermission, actual: &Permission) -> bool {
    match required {
        MethodPermission::Public => true,
        // Never reaches here — the middleware answers socket-only methods before any
        // signature exists. Returning false keeps it that way if the order ever changes.
        MethodPermission::LocalOnly => false,
        MethodPermission::Authenticated => true, // signature already validated
        MethodPermission::OwnerOnly => *actual == Permission::Owner,
        MethodPermission::Whitelist => {
            *actual == Permission::Owner || *actual == Permission::Whitelist
        }
    }
}

/// Validate signature and return signer address
fn validate_signature(
    signature: Option<String>,
    timestamp_str: Option<String>,
    method_name: &str,
) -> Result<String, Status> {
    // Check signature
    let sig = signature.ok_or_else(|| {
        warn!(
            method = %method_name,
            event = "AUTH_MISSING_SIGNATURE",
            "Signature missing in request"
        );
        Status::unauthenticated("Missing signature. Please provide 'x-signature' in metadata")
    })?;

    let ts_str = timestamp_str.ok_or_else(|| {
        warn!(
            method = %method_name,
            event = "AUTH_MISSING_TIMESTAMP",
            "Timestamp missing in request"
        );
        Status::unauthenticated("Missing timestamp. Please provide 'x-timestamp' in metadata")
    })?;

    let timestamp: i64 = ts_str.parse().map_err(|_| {
        warn!(
            method = %method_name,
            timestamp = %ts_str,
            event = "AUTH_INVALID_TIMESTAMP",
            "Invalid timestamp format"
        );
        Status::invalid_argument("Invalid timestamp format")
    })?;

    // Verify timestamp is within acceptable window
    if !verify_timestamp(timestamp).unwrap_or(false) {
        warn!(
            method = %method_name,
            timestamp = %timestamp,
            event = "AUTH_TIMESTAMP_EXPIRED",
            "Timestamp outside acceptable window"
        );
        return Err(Status::unauthenticated(
            "Timestamp outside acceptable window (±2 minutes)",
        ));
    }

    // Build the message that should have been signed
    let message = build_sign_message(method_name, timestamp);

    // Recover signer address from signature
    let signer_address = recover_evm_address(&message, &sig).map_err(|e| {
        warn!(
            method = %method_name,
            error = %e,
            event = "AUTH_SIGNATURE_RECOVERY_FAILED",
            "Failed to recover signer address"
        );
        Status::unauthenticated(format!("Invalid signature: {}", e))
    })?;

    debug!(
        method = %method_name,
        signer = %signer_address,
        "Successfully recovered signer address"
    );

    Ok(signer_address)
}
