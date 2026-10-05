use crate::config::PermissionConfig;
use crate::permission::{Permission, PermissionManager};
use crate::signature_auth::{
    build_sign_message_v2, recover_evm_address, verify_timestamp, ReplayGuard, MAX_TIMESTAMP_DIFF,
};
use sha2::Digest;
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
    /// Signatures already used, shared across both listeners (TCP and socket) —
    /// one execution per signature, whichever path it arrives on.
    replay: Arc<ReplayGuard>,
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
            replay: Arc::new(ReplayGuard::default()),
        }
    }

    pub fn with_permission_manager(permission_manager: Arc<PermissionManager>) -> Self {
        Self {
            permission_manager: Some(permission_manager),
            enabled: true,
            replay: Arc::new(ReplayGuard::default()),
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
            replay: self.replay.clone(),
        }
    }
}

/// Middleware that performs signature validation and permission checks
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    permission_manager: Option<Arc<PermissionManager>>,
    enabled: bool,
    replay: Arc<ReplayGuard>,
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
        let replay = self.replay.clone();

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
            let Some(signature) = req
                .headers()
                .get("x-signature")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
            else {
                warn!(
                    method = %method_name,
                    event = "AUTH_MISSING_SIGNATURE",
                    "Signature missing in request"
                );
                return Ok(Status::unauthenticated(
                    "Missing signature. Please provide 'x-signature' in metadata",
                )
                .into_http());
            };

            let timestamp_str = req
                .headers()
                .get("x-timestamp")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Only body-bound signatures ("x-signature-version: 2") are accepted.
            // The legacy "method:timestamp" message authorised the method with ANY
            // body, so an observed signature could carry a different request.
            let body_bound = req
                .headers()
                .get("x-signature-version")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim() == "2")
                .unwrap_or(false);
            if !body_bound {
                warn!(
                    method = %method_name,
                    event = "AUTH_LEGACY_SIGNATURE_REFUSED",
                    "Refused a signature that does not cover the request body"
                );
                return Ok(Status::unauthenticated(
                    "this node accepts only body-bound signatures (x-signature-version: 2): \
                     use tapp-cli >= 0.9.0, without --legacy-sign",
                )
                .into_http());
            }

            // Hash exactly the bytes that will be decoded — the server's own view of
            // the request, not a re-encoding of it. The body is buffered, hashed and
            // handed on unchanged.
            let (parts, body) = req.into_parts();
            let bytes = match http_body_util::BodyExt::collect(http_body_util::Limited::new(
                body,
                MAX_SIGNED_BODY_BYTES,
            ))
            .await
            {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    warn!(method = %method_name, error = %e, "Could not read request body");
                    return Ok(Status::invalid_argument(format!(
                        "could not read the request body: {e}"
                    ))
                    .into_http());
                }
            };
            let body_hash = match unary_message_hash(&bytes) {
                Ok(h) => h,
                Err(e) => return Ok(Status::invalid_argument(e).into_http()),
            };
            req = http::Request::from_parts(
                parts,
                tonic::body::boxed(http_body_util::Full::new(bytes)),
            );

            // Validate signature
            let (signer_address, signed_ts) =
                match validate_signature(&signature, timestamp_str, &method_name, &body_hash) {
                    Ok(v) => v,
                    Err(status) => return Ok(status.into_http()),
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

            // One execution per signed request. Recorded only once permission has
            // passed: any 65 bytes recover to SOME address, so admitting earlier
            // would let anyone grow the guard with requests that were never going
            // to run. Keyed on signer + signed message, not the signature string.
            let signed_message = build_sign_message_v2(&method_name, &body_hash, signed_ts);
            if !replay.admit(&signer_address, &signed_message, signed_ts) {
                warn!(
                    method = %method_name,
                    signer = %signer_address,
                    event = "AUTH_SIGNATURE_REPLAYED",
                    "Refused a signature that was already used"
                );
                return Ok(Status::unauthenticated(
                    "this signature was already used; sign the request again",
                )
                .into_http());
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
        // GetAppCsr is here rather than beside GetAppTlsCert deliberately: a signing
        // request publishes a public key and a name, which the certificate it becomes
        // would publish anyway. It is the private key that makes the other one local.
        "GetEvidence" | "GetAppKey" | "GetAppInfo" | "ListApps" | "GetTaskStatus"
        | "GetServiceStatus" | "GetTappInfo" | "GetAppCsr" => MethodPermission::Public,

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

/// tonic's default `max_decoding_message_size` (4 MiB) plus the 5-byte gRPC frame
/// header. A larger body would be refused by the decoder anyway; capping the
/// buffer here keeps an unauthenticated caller from making this layer hold more.
const MAX_SIGNED_BODY_BYTES: usize = 4 * 1024 * 1024 + 5;

/// sha256 of the single protobuf message inside a unary gRPC request body
/// (`flag:u8 ‖ len:u32be ‖ message`). This is exactly what a client gets from
/// `prost::Message::encode_to_vec` on the request it is about to send.
fn unary_message_hash(body: &[u8]) -> Result<[u8; 32], String> {
    if body.len() < 5 {
        return Err("request body is not a gRPC message".into());
    }
    if body[0] != 0 {
        return Err(
            "compressed requests cannot carry a body-bound signature; disable request \
             compression"
                .into(),
        );
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if body.len() != 5 + len {
        return Err("a body-bound signature covers exactly one request message".into());
    }
    Ok(sha2::Sha256::digest(&body[5..]).into())
}

/// Validate a body-bound signature (`method:0x<sha256(body)>:timestamp`) and
/// return `(signer address, signed timestamp)`.
fn validate_signature(
    sig: &str,
    timestamp_str: Option<String>,
    method_name: &str,
    body_hash: &[u8; 32],
) -> Result<(String, i64), Status> {
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
    if !verify_timestamp(timestamp) {
        warn!(
            method = %method_name,
            timestamp = %timestamp,
            event = "AUTH_TIMESTAMP_EXPIRED",
            "Timestamp outside acceptable window"
        );
        return Err(Status::unauthenticated(format!(
            "Timestamp outside acceptable window (±{} seconds)",
            MAX_TIMESTAMP_DIFF
        )));
    }

    // Build the message that should have been signed
    let message = build_sign_message_v2(method_name, body_hash, timestamp);

    // Recover signer address from signature
    let signer_address = recover_evm_address(&message, sig).map_err(|e| {
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

    Ok((signer_address, timestamp))
}

/// The signed-body path end to end, through the real middleware: real signatures,
/// real gRPC framing, the body buffered and handed on. Unit tests of the pieces
/// would pass while the seam between them (what the client hashes vs what the
/// server hashes) was wrong, which is the one thing that matters here.
#[cfg(test)]
mod signed_body_tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use prost::Message;
    use sha3::Keccak256;
    use std::sync::Mutex;
    use tonic::codegen::Bytes;

    const KEY: [u8; 32] = [7u8; 32];
    const OTHER_KEY: [u8; 32] = [9u8; 32];

    fn address_of(key: &[u8; 32]) -> String {
        let sk = SigningKey::from_slice(key).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    /// EIP-191 personal_sign, r‖s‖v with v = 27/28 — what tapp-cli produces.
    fn personal_sign(key: &[u8; 32], message: &str) -> String {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let sk = SigningKey::from_slice(key).unwrap();
        let (sig, rid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(rid.to_byte() + 27);
        format!("0x{}", hex::encode(bytes))
    }

    fn frame(message: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&(message.len() as u32).to_be_bytes());
        out.extend_from_slice(message);
        out
    }

    fn start_app(compose: &str) -> crate::proto::StartAppRequest {
        crate::proto::StartAppRequest {
            compose_content: compose.into(),
            app_id: "demo".into(),
            ..Default::default()
        }
    }

    /// What the inner service saw: the body bytes and the authenticated signer.
    type Seen = Arc<Mutex<Option<(Vec<u8>, Option<String>)>>>;

    fn middleware() -> (AuthMiddleware<impl Service<
        http::Request<BoxBody>,
        Response = http::Response<BoxBody>,
        Error = std::convert::Infallible,
        Future = impl Send,
    > + Clone + Send + 'static>, Seen) {
        let seen: Seen = Arc::new(Mutex::new(None));
        let record = seen.clone();
        let inner = tower::service_fn(move |req: http::Request<BoxBody>| {
            let record = record.clone();
            async move {
                let signer = req.extensions().get::<SignerAddress>().map(|s| s.0.clone());
                let body = http_body_util::BodyExt::collect(req.into_body())
                    .await
                    .map(|c| c.to_bytes().to_vec())
                    .unwrap_or_default();
                *record.lock().unwrap() = Some((body, signer));
                Ok::<_, std::convert::Infallible>(http::Response::new(tonic::body::empty_body()))
            }
        });
        let pm = Arc::new(PermissionManager::new(Some(address_of(&KEY))));
        let layer = AuthLayer::with_permission_manager(pm);
        (layer.layer(inner), seen)
    }

    fn request(
        method: &str,
        body: Vec<u8>,
        signature: &str,
        timestamp: i64,
        version: Option<&str>,
    ) -> http::Request<BoxBody> {
        let mut b = http::Request::builder()
            .uri(format!("http://node/tapp_service.TappService/{method}"))
            .header("x-signature", signature)
            .header("x-timestamp", timestamp.to_string());
        if let Some(v) = version {
            b = b.header("x-signature-version", v);
        }
        b.body(tonic::body::boxed(http_body_util::Full::new(Bytes::from(body))))
            .unwrap()
    }

    /// The grpc-status a refusal carries; None = the request reached the service.
    fn grpc_status(resp: &http::Response<BoxBody>) -> Option<i32> {
        resp.headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    }

    fn signed_v2(key: &[u8; 32], method: &str, msg: &crate::proto::StartAppRequest, ts: i64) -> String {
        let hash: [u8; 32] = sha2::Sha256::digest(msg.encode_to_vec()).into();
        personal_sign(key, &build_sign_message_v2(method, &hash, ts))
    }

    #[tokio::test]
    async fn a_body_bound_signature_from_the_owner_passes_and_the_body_arrives_intact() {
        let (mut svc, seen) = middleware();
        let msg = start_app("services: {}");
        let ts = chrono::Utc::now().timestamp();
        let sig = signed_v2(&KEY, "StartApp", &msg, ts);
        let body = frame(&msg.encode_to_vec());

        let resp = svc
            .call(request("StartApp", body.clone(), &sig, ts, Some("2")))
            .await
            .unwrap();
        assert_eq!(grpc_status(&resp), None, "the owner's request must reach the service");
        let (got_body, signer) = seen.lock().unwrap().clone().expect("service was called");
        assert_eq!(got_body, body, "the buffered body must be handed on byte for byte");
        assert_eq!(signer.as_deref(), Some(address_of(&KEY).as_str()));
    }

    #[tokio::test]
    async fn a_body_swapped_in_flight_is_refused() {
        let (mut svc, seen) = middleware();
        let signed_for = start_app("services: {web: {image: nginx}}");
        let ts = chrono::Utc::now().timestamp();
        let sig = signed_v2(&KEY, "StartApp", &signed_for, ts);
        // Same signature, different compose: the interceptor's move.
        let swapped = start_app("services: {web: {image: evil}}");

        let resp = svc
            .call(request("StartApp", frame(&swapped.encode_to_vec()), &sig, ts, Some("2")))
            .await
            .unwrap();
        // Recovers some unrelated address, which holds no permission.
        assert_eq!(grpc_status(&resp), Some(tonic::Code::PermissionDenied as i32));
        assert!(seen.lock().unwrap().is_none(), "the swapped request must not reach the service");
    }

    #[tokio::test]
    async fn a_signature_is_good_for_one_execution() {
        let (mut svc, _) = middleware();
        let msg = start_app("services: {}");
        let ts = chrono::Utc::now().timestamp();
        let sig = signed_v2(&KEY, "StartApp", &msg, ts);
        let body = frame(&msg.encode_to_vec());

        let first = svc.call(request("StartApp", body.clone(), &sig, ts, Some("2"))).await.unwrap();
        assert_eq!(grpc_status(&first), None);
        let replay = svc.call(request("StartApp", body, &sig, ts, Some("2"))).await.unwrap();
        assert_eq!(grpc_status(&replay), Some(tonic::Code::Unauthenticated as i32));
    }

    /// One signature has many spellings that recover to the same signer. Every one
    /// of them is the same request, and must be refused as a replay.
    #[tokio::test]
    async fn a_re_encoded_signature_is_still_a_replay() {
        let (mut svc, _) = middleware();
        let msg = start_app("services: {}");
        let ts = chrono::Utc::now().timestamp();
        let sig = signed_v2(&KEY, "StartApp", &msg, ts);
        let body = frame(&msg.encode_to_vec());

        let first = svc.call(request("StartApp", body.clone(), &sig, ts, Some("2"))).await.unwrap();
        assert_eq!(grpc_status(&first), None);

        let hex = sig.trim_start_matches("0x");
        let v = u8::from_str_radix(&hex[128..], 16).unwrap();
        let variants = [
            hex.to_string(),                                       // no 0x
            format!("0x{}", hex.to_uppercase()),                   // other case
            format!("0x{}{:02x}", &hex[..128], v - 27),            // v as 0/1
        ];
        for variant in variants {
            let resp = svc
                .call(request("StartApp", body.clone(), &variant, ts, Some("2")))
                .await
                .unwrap();
            assert_eq!(
                grpc_status(&resp),
                Some(tonic::Code::Unauthenticated as i32),
                "{variant} is the same signature and must be refused as a replay"
            );
        }
    }

    /// Any 65 bytes recover to SOME address, so a request that fails permission
    /// must not be remembered — otherwise anyone could grow the guard at will.
    #[tokio::test]
    async fn a_request_refused_for_permission_leaves_nothing_in_the_guard() {
        let (mut svc, _) = middleware();
        let msg = start_app("services: {}");
        let ts = chrono::Utc::now().timestamp();
        for key in [OTHER_KEY, [11u8; 32], [13u8; 32]] {
            let sig = signed_v2(&key, "StartApp", &msg, ts);
            let resp = svc
                .call(request("StartApp", frame(&msg.encode_to_vec()), &sig, ts, Some("2")))
                .await
                .unwrap();
            assert_eq!(grpc_status(&resp), Some(tonic::Code::PermissionDenied as i32));
        }
        assert_eq!(svc.replay.len(), 0);
    }

    #[tokio::test]
    async fn the_window_is_ten_minutes() {
        let (mut svc, _) = middleware();
        let msg = start_app("services: {}");
        let body = frame(&msg.encode_to_vec());
        let now = chrono::Utc::now().timestamp();

        let ts = now - 480;
        let sig = signed_v2(&KEY, "StartApp", &msg, ts);
        let resp = svc.call(request("StartApp", body.clone(), &sig, ts, Some("2"))).await.unwrap();
        assert_eq!(grpc_status(&resp), None, "8 minutes old is inside the window");

        let ts = now - 660;
        let sig = signed_v2(&KEY, "StartApp", &msg, ts);
        let resp = svc.call(request("StartApp", body, &sig, ts, Some("2"))).await.unwrap();
        assert_eq!(grpc_status(&resp), Some(tonic::Code::Unauthenticated as i32));
    }

    /// The legacy message authorised the method with any body. Even a valid one
    /// from the owner is refused — and refused before the body is read.
    #[tokio::test]
    async fn a_legacy_signature_is_refused_even_from_the_owner() {
        let (mut svc, seen) = middleware();
        let msg = start_app("services: {}");
        let ts = chrono::Utc::now().timestamp();
        let sig = personal_sign(&KEY, &format!("StartApp:{ts}"));
        let resp = svc
            .call(request("StartApp", frame(&msg.encode_to_vec()), &sig, ts, None))
            .await
            .unwrap();
        assert_eq!(grpc_status(&resp), Some(tonic::Code::Unauthenticated as i32));
        assert!(seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn a_body_bound_signature_from_someone_else_holds_no_permission() {
        let (mut svc, _) = middleware();
        let msg = start_app("services: {}");
        let ts = chrono::Utc::now().timestamp();
        let sig = signed_v2(&OTHER_KEY, "StartApp", &msg, ts);
        let resp = svc
            .call(request("StartApp", frame(&msg.encode_to_vec()), &sig, ts, Some("2")))
            .await
            .unwrap();
        assert_eq!(grpc_status(&resp), Some(tonic::Code::PermissionDenied as i32));
    }

    #[test]
    fn framing_is_checked_before_anything_is_hashed() {
        assert!(unary_message_hash(&[0, 0, 0]).is_err(), "short");
        assert!(unary_message_hash(&[1, 0, 0, 0, 0]).is_err(), "compressed");
        let mut two = frame(b"a");
        two.extend(frame(b"b"));
        assert!(unary_message_hash(&two).is_err(), "more than one message");
        // An empty message (AcceptOwnerRequest {}) is a valid, hashable body.
        assert_eq!(
            unary_message_hash(&frame(b"")).unwrap(),
            <[u8; 32]>::from(sha2::Sha256::digest(b""))
        );
    }
}
