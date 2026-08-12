// Shared modules re-exported from tapp-common (no TEE/Docker deps)
pub use tapp_common::app_key;
pub use tapp_common::onchain;
pub use tapp_common::error;
pub use tapp_common::report_data;
pub use tapp_common::verify;
pub use tapp_common::proto;
pub use tapp_common::as_proto;

// Server-only modules
pub mod auth_layer;
pub mod balance_withdrawal;
pub mod kms_client;
pub mod boot;
pub mod config;
pub mod measurement_service;
pub mod nonce_manager;
pub use tapp_common::pinned_tls;
pub mod permission;
pub mod service_monitor;
pub mod signature_auth;
pub mod task_manager;
pub mod tls_cert;
pub mod utils;

pub use boot::BootService;
pub use config::TappConfig;
pub use tapp_common::error::{TappError, TappResult};
use std::collections::HashMap;
use std::sync::Arc;
pub use task_manager::TaskStatus;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};


// // Re-export common types
pub use proto::{
    tapp_service_client::TappServiceClient,
    tapp_service_server::{TappService, TappServiceServer},
    *,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Runtime configuration set via ClaimConfig (owner/chain/kbs).
/// Separate from the static TappConfig so get-tapp-info can show live values.
#[derive(Debug, Clone, Default)]
pub struct ClaimedRuntimeConfig {
    pub chain_rpc_url: String,
    pub chain_contract_address: String,
    pub kbs_node_urls: Vec<String>,
    /// Empty means "not claimed" — fall back to config.toml, which is the pre-baked mode.
    pub tls_key_source: String,
    /// The verifier this tapp believes about KMS node identity, and the sha256 of that
    /// verifier's TLS public key. Claim-time or `UpdateTrustAnchors`; deliberately not in
    /// config.toml, for the same reason as the owner — a field there lives in the CVM image,
    /// so one image per verifier deployment and one set of reference values each.
    ///
    /// Empty means KMS node identity cannot be checked. That is a real state, not a
    /// degraded-but-fine one: it is the difference between "checked and passed" and "not
    /// checked", and callers must not conflate them.
    pub scan_url: String,
    pub scan_public_key: String,
}

/// Reject anything that is not a usable (url, pin) pair, or accept "both empty" as
/// "leave alone".
///
/// Validated here, at the boundary where a human typed it, rather than at connect time
/// deep inside the KMS client: a malformed pin discovered on the first key fetch of a
/// production app is a much worse place to find out.
fn validate_scan_anchor(url: &str, pin: &str) -> Result<Option<(String, String)>, String> {
    if url.is_empty() && pin.is_empty() {
        return Ok(None);
    }
    if url.is_empty() || pin.is_empty() {
        return Err(
            "scan_url and scan_public_key must be given together: a URL without a pin is an \
             unauthenticated channel carrying a verdict, and a pin without a URL names nothing"
                .to_string(),
        );
    }
    // A pinned key delivered over plaintext proves nothing — anyone on the path replaces
    // the whole response, pin check included, because there is no channel to bind it to.
    if !url.starts_with("https://") {
        return Err(format!(
            "scan_url must be https (got {:?}): pinning a key on a plaintext channel proves \
             nothing",
            url
        ));
    }
    let hex_part = pin.strip_prefix("0x").unwrap_or(pin);
    if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "scan_public_key must be a 32-byte sha256 in hex, got {} hex chars",
            hex_part.len()
        ));
    }
    Ok(Some((
        url.to_string(),
        format!("0x{}", hex_part.to_lowercase()),
    )))
}

/// The KMS app id whose attested keys are the ones to accept.
///
/// Fixed rather than configurable: it names the cluster this tapp fetches key material
/// from, and a node that could be pointed at a different app's keys would be pointed at
/// a different cluster's, which is the substitution being prevented.
const KMS_APP_ID: &str = "0g-kms";

/// Build a KMS client that verifies node identity when a verifier is configured.
///
/// Unconfigured, it behaves exactly as before — unverified. That is the weaker mode and
/// is logged as such: a tapp that has never been told which verifier to believe cannot
/// invent one, and refusing to start would strand every existing node.
fn kms_client_with_anchor(
    node_urls: Vec<String>,
    retry: &config::RetryConfig,
    scan_url: &str,
    scan_pubkey: &str,
) -> kms_client::KmsClient {
    let c = kms_client::KmsClient::new(node_urls, retry);
    if scan_url.is_empty() || scan_pubkey.is_empty() {
        tracing::warn!(
            event = "KMS_UNVERIFIED",
            "No verifier configured — KMS node identity will NOT be checked. Set one with \
             claim-config --scan-url/--scan-pubkey or update-trust-anchors."
        );
        return c;
    }
    info!(scan = %scan_url, "KMS nodes will be verified against attested keys");
    c.with_verifier(
        scan_url.to_string(),
        scan_pubkey.to_string(),
        KMS_APP_ID.to_string(),
    )
}

pub struct TappServiceImpl {
    pub config: TappConfig,
    pub boot_service: Arc<BootService>,
    pub app_key_service: Arc<app_key::AppKeyService>,
    /// KMS client, wrapped in RwLock so ClaimConfig can initialize it at runtime
    /// if kbs_node_urls were not baked into config.toml (dynamic mode).
    pub kms_client: Arc<tokio::sync::RwLock<Option<kms_client::KmsClient>>>,
    pub nonce_manager: nonce_manager::NonceManager,
    pub logs_service: service_monitor::logs::LogsService,
    pub permission_manager: Option<Arc<permission::PermissionManager>>,
    pub measurement_service: Arc<measurement_service::MeasurementService>,
    /// Runtime config set by ClaimConfig or establish_owner_at_startup.
    pub claimed_runtime_config: Arc<tokio::sync::RwLock<ClaimedRuntimeConfig>>,
    /// Per-app TLS identity, derived on first use. Same lifetime as the app key cache:
    /// the key itself is deterministic, so a restart re-derives the identical one.
    pub tls_identities: Arc<Mutex<HashMap<String, Arc<tls_cert::TlsIdentity>>>>,
}

/// Fetch a KMS-derived secret for `app_id` under the `material` namespace.
///
/// Shared by `GetSecretResource`, TLS key derivation and volume-key derivation, so
/// all authenticate to KMS the same way — with the app's own signer — and none can
/// drift into a second convention. A free function (not a method) because the
/// volume path runs it inside the spawned start task, which holds clones of these
/// two handles rather than `&self`.
async fn kms_derive_with(
    kms_client: &tokio::sync::RwLock<Option<kms_client::KmsClient>>,
    app_key_service: &app_key::AppKeyService,
    app_id: &str,
    material: &str,
) -> Result<Vec<u8>, Status> {
    let kms_guard = kms_client.read().await;
    let kms = kms_guard.as_ref().ok_or_else(|| {
        Status::failed_precondition(
            "KMS not configured — set [kbs] node_urls in config.toml or call claim-config \
             with --kbs-urls",
        )
    })?;

    // Create-if-missing first. `get_private_key` below only reads the cache, so without
    // this a KMS request fails outright when it is the app's very first call — which is
    // exactly what happens when an app asks for its TLS certificate before anything
    // else has touched its key.
    app_key_service
        .get_app_key(app_id, "ethereum", false)
        .await
        .map_err(|e| Status::internal(format!("Failed to create app key: {}", e)))?;

    // Get in-memory key pair: private key for signing + decryption, pubkey for KMS encryption target
    let private_key = app_key_service
        .get_private_key(app_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get app key: {}", e)))?;

    let (_, secp256k1_pubkey_64, _) = app_key_service
        .get_public_key(app_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get app public key: {}", e)))?;

    // ecies expects uncompressed secp256k1 pubkey: 0x04 || 64 bytes
    let pubkey_uncompressed = [&[0x04u8], secp256k1_pubkey_64.as_slice()].concat();
    let pubkey_hex = hex::encode(&pubkey_uncompressed);

    // Sign KMS request: EIP-191 personal_sign over "GetSecretResource:{timestamp}"
    // (KMS server verifies via ecrecover, so signature must be 65-byte r||s||v).
    let timestamp = chrono::Utc::now().timestamp();
    let message = signature_auth::build_sign_message("GetSecretResource", timestamp);
    let signature = app_key::sign_message_eip191(&private_key, message.as_bytes())
        .map_err(|e| Status::internal(format!("Failed to sign KMS request: {}", e)))?;
    let signature_hex = hex::encode(&signature);

    // Call KMS cluster → get ECIES-encrypted app key. `material` is opaque
    // derivation material forwarded verbatim (empty = omitted, derives
    // purely from the app_id namespace as before) — see issue #33.
    let encrypted = kms
        .get_encrypted_secret(app_id, timestamp, &pubkey_hex, &signature_hex, material)
        .await
        .map_err(|e| Status::unavailable(format!("KMS request failed: {}", e)))?;

    // Decrypt with our private key
    ecies::decrypt(&private_key, &encrypted)
        .map_err(|e| Status::internal(format!("Failed to decrypt KMS secret: {}", e)))
}

impl TappServiceImpl {
    /// See [`kms_derive_with`].
    async fn kms_derive(&self, app_id: &str, material: &str) -> Result<Vec<u8>, Status> {
        kms_derive_with(&self.kms_client, &self.app_key_service, app_id, material).await
    }

    /// The app's TLS identity, derived on first use and kept for the process lifetime.
    ///
    /// Cached because the certificate is asked for on every app start and every renewal
    /// check while the key behind it does not change within a boot — and because
    /// `GetEvidence` needs the public key without being allowed to trigger a KMS round trip
    /// of its own (it is unauthenticated; an outside caller must not be able to drive KMS
    /// traffic).
    ///
    /// Where the key comes from is a real choice, not a fallback — see
    /// [`config::TlsKeySource`].
    async fn tls_identity(&self, app_id: &str) -> Result<Arc<tls_cert::TlsIdentity>, Status> {
        if let Some(id) = self.tls_identities.lock().await.get(app_id) {
            return Ok(id.clone());
        }
        let (source, secret) = self.tls_key_material(app_id).await?;

        let ca_url = self.config.server.ca_url.clone();
        let id = Arc::new(
            tls_cert::build(app_id, &secret, source.as_str(), ca_url.as_deref())
                .await
                .map_err(|e| Status::internal(format!("{}", e)))?,
        );
        self.tls_identities
            .lock()
            .await
            .insert(app_id.to_string(), id.clone());
        Ok(id)
    }

    /// The app's TLS key material and where it came from.
    ///
    /// Split out so a signing request is built from the same bytes as the certificate. Two
    /// derivations reached by two routes would be a place for the certified key and the
    /// attested key to drift apart, which is the one thing this must not do.
    async fn tls_key_material(
        &self,
        app_id: &str,
    ) -> Result<(config::TlsKeySource, Vec<u8>), Status> {
        // Claimed value wins over the pre-baked one, same as chain and KBS config.
        let source = match self
            .claimed_runtime_config
            .read()
            .await
            .tls_key_source
            .as_str()
        {
            "kms" => config::TlsKeySource::Kms,
            "local" => config::TlsKeySource::Local,
            _ => self.config.server.tls_key_source,
        };
        let secret = match source {
            config::TlsKeySource::Local => {
                // Create-if-missing, then derive from the signer. `get_private_key` only
                // reads the cache, so an app asking for a certificate as its first action
                // would otherwise find nothing.
                self.app_key_service
                    .get_app_key(app_id, "ethereum", false)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to create app key: {}", e)))?;
                let signer_key = self
                    .app_key_service
                    .get_private_key(app_id)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to get app key: {}", e)))?;
                tls_cert::derive_from_signer(&signer_key)
            }
            config::TlsKeySource::Kms => {
                let secret = self
                    .kms_derive(app_id, tls_cert::KMS_MATERIAL)
                    .await
                    .map_err(|e| {
                        Status::failed_precondition(format!(
                            "cannot derive the TLS key for {}: {}",
                            app_id, e
                        ))
                    })?;
                // Taking a derived secret is a measured event wherever it happens, so a key
                // pulled for TLS shows up in the runtime log exactly like one pulled by the
                // app itself. The local path has nothing to measure — no secret moved.
                self.measure_secret_resource(app_id, tls_cert::KMS_MATERIAL, true)
                    .await;
                secret
            }
        };
        Ok((source, secret))
    }

    /// The TLS public key hash to put in `report_data`, if one has been derived.
    ///
    /// Absent means no TLS key exists yet for this app — not that one is being withheld.
    /// The two are distinguishable in practice: an endpoint serving TLS whose evidence
    /// names no key fails the comparison a verifier makes.
    async fn tls_public_key_for_evidence(&self, app_id: &str) -> Option<String> {
        self.tls_identities
            .lock()
            .await
            .get(app_id)
            .map(|id| format!("0x{}", id.public_key_sha256))
    }

    /// Record that a KMS-derived secret left this node, into RTMR3.
    ///
    /// Without this, a derived key can be pulled by any container on the box and nothing
    /// in the attestation says it happened — `get_app_secret_key` has always been measured,
    /// but this path, which is how a key derived from the KMS namespace is obtained, was
    /// not. It is what makes "re-acquiring a key leaves a trace" true rather than assumed.
    ///
    /// `material` is recorded because it names the derivation namespace, which is the part
    /// that says *which* secret was taken. Failure to measure never fails the request: the
    /// caller already holds the secret by this point, so refusing to answer would hide the
    /// event rather than prevent it.
    async fn measure_secret_resource(&self, app_id: &str, material: &str, success: bool) {
        // Best-effort: an app fetching a secret before its measurements are known is
        // unusual but must still be recorded, so missing app_info leaves empty hashes
        // rather than skipping the event.
        let info = self.boot_service.get_app_info(app_id).await.ok().flatten();
        let m = boot::AppMeasurement {
            app_id: app_id.to_string(),
            operation: measurement_service::OPERATION_NAME_GET_SECRET_RESOURCE.to_string(),
            result: String::new(),
            error: None,
            compose_hash: info
                .as_ref()
                .map(|i| i.compose_content.hash.clone())
                .unwrap_or_default(),
            volumes_hash: info
                .as_ref()
                .map(|i| i.mount_files.hash.clone())
                .unwrap_or_default(),
            image_hash: info
                .as_ref()
                .map(|i| i.compose_content.image_hash.clone())
                .unwrap_or_default(),
            deployer: info.as_ref().map(|i| i.owner.clone()).unwrap_or_default(),
            timestamp: utils::current_timestamp(),
        };
        let m = if success {
            m.with_success()
        } else {
            m.with_failure("KMS request or decryption failed".to_string())
        };

        // `material` has no field on AppMeasurement, so it is added to the serialised
        // object rather than changing a struct every other measured operation shares.
        let mut payload = match serde_json::to_value(&m) {
            Ok(serde_json::Value::Object(o)) => o,
            _ => {
                tracing::error!("failed to serialise get_secret_resource measurement");
                return;
            }
        };
        payload.insert(
            "material".to_string(),
            serde_json::Value::String(material.to_string()),
        );

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_GET_SECRET_RESOURCE,
                &serde_json::Value::Object(payload).to_string(),
            )
            .await
        {
            tracing::error!("Failed to extend measurement for get_secret_resource: {}", e);
        }
    }

    pub async fn new(
        config: TappConfig,
        permission_manager: Option<Arc<permission::PermissionManager>>,
        measurement_service: Arc<measurement_service::MeasurementService>,
    ) -> TappResult<Self> {
        info!("Initializing TAPP service components");

        // Initialize TaskManager
        let task_manager = Arc::new(task_manager::TaskManager::new());

        // Initialize BootService with measurement_service and task_manager
        let boot_service =
            Arc::new(BootService::new(measurement_service.clone(), task_manager).await?);

        // Initialize AppKeyService (always in-memory, independent of KBS).
        // Arc because volume-key derivation runs inside the spawned start task,
        // which needs its own handle (see start_app).
        let app_key_service = Arc::new(app_key::AppKeyService::new());

        // Initialize NonceManager for replay attack prevention
        let nonce_manager = nonce_manager::NonceManager::new();

        // Initialize LogsService
        let logs_service =
            service_monitor::logs::LogsService::new(config.logging.file_path.clone());

        // Initialize KMS client from KBS config (used for GetSecretResource).
        // Wrapped in Arc<RwLock> so ClaimConfig can (re-)initialize it at runtime
        // when kbs_node_urls are provided dynamically instead of baked in config.
        let kms_client = Arc::new(tokio::sync::RwLock::new(config.kbs.as_ref().map(|kbs| {
            info!(nodes = kbs.node_urls.len(), "Initializing KMS client from KBS config");
            kms_client::KmsClient::new(kbs.node_urls.clone(), &kbs.retry)
        })));

        // Initialize runtime config from static config (pre-baked values visible immediately)
        let claimed_runtime_config = Arc::new(tokio::sync::RwLock::new(ClaimedRuntimeConfig {
            chain_rpc_url: config.chain.as_ref().map(|c| c.rpc_url.clone()).unwrap_or_default(),
            chain_contract_address: config.chain.as_ref().map(|c| c.contract_address.clone()).unwrap_or_default(),
            kbs_node_urls: config.kbs.as_ref().map(|k| k.node_urls.clone()).unwrap_or_default(),
            tls_key_source: config.server.tls_key_source.as_str().to_string(),
            // No static counterpart on purpose: these are claimed, never baked into the
            // image. See ClaimedRuntimeConfig.
            scan_url: String::new(),
            scan_public_key: String::new(),
        }));

        info!("All TAPP service components initialized successfully");

        Ok(Self {
            tls_identities: Arc::new(Mutex::new(HashMap::new())),
            boot_service,
            app_key_service,
            kms_client,
            nonce_manager,
            logs_service,
            permission_manager,
            measurement_service,
            claimed_runtime_config,
            config,
        })
    }
}

/// Establish the tapp owner at startup and return it (None = boots unclaimed,
/// awaiting the ClaimConfig RPC). Sources, in order of resolution:
///
/// - config `owner_address` (legacy baked-in mode) — measured as a
///   `claim_config` event the first time it takes effect in a boot (chain/kbs
///   values from the same config are included in the measurement data);
/// - the owner persisted by a previous tapp-server process of the SAME boot
///   (restored silently: its claim_config event is already in this boot's
///   runtime event log);
/// - neither → unclaimed.
///
/// A config/persisted mismatch is a hard error.
pub async fn establish_owner_at_startup(
    pm: &Arc<permission::PermissionManager>,
    measurement_service: &Arc<measurement_service::MeasurementService>,
    config_owner: Option<&str>,
    chain_rpc_url: &str,
    chain_contract_address: &str,
    kbs_node_urls: &[String],
) -> Result<Option<String>, String> {
    let config_owner =
        config_owner.map(permission::PermissionManager::normalize_address);
    let persisted = pm.load_persisted_owner();

    let (owner, needs_measurement) = match (config_owner, persisted) {
        (Some(c), Some(p)) => {
            if c != p {
                return Err(format!(
                    "Owner mismatch: config says {} but this boot already claimed {}",
                    c, p
                ));
            }
            (Some(c), false) // measured earlier this boot
        }
        (Some(c), None) => (Some(c), true),
        (None, Some(p)) => (Some(p), false),
        (None, None) => (None, false),
    };

    if let Some(owner) = &owner {
        pm.set_owner(owner).await;

        if needs_measurement {
            let measurement_data = serde_json::json!({
                "operation": measurement_service::OPERATION_NAME_CLAIM_CONFIG,
                "owner": owner,
                "chain_rpc_url": chain_rpc_url,
                "chain_contract_address": chain_contract_address,
                "kbs_node_urls": kbs_node_urls,
                "timestamp": utils::current_timestamp()
            })
            .to_string();

            if let Err(e) = measurement_service
                .extend_measurement(
                    measurement_service::OPERATION_NAME_CLAIM_CONFIG,
                    &measurement_data,
                )
                .await
            {
                error!(error = %e, "Failed to extend claim_config measurement at startup");
            }

            if let Err(e) = pm.persist_owner().await {
                tracing::warn!(error = %e, "Failed to persist owner at startup");
            }
        }
    }

    Ok(owner)
}

#[tonic::async_trait]
impl TappService for TappServiceImpl {
    /// Get attestation evidence from TEE platform
    async fn get_evidence(
        &self,
        request: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        info!("Calling GetEvidence");
        debug!("Request: {:?}", request);
        let req = request.into_inner();
        // Use the app signer (TEE-derived ethereum address) as report_data so the
        // attestation binds to the on-chain registered signer.
        let key_pair = self
            .app_key_service
            .get_app_key(&req.app_id, "ethereum", false)
            .await?;
        // Reported only if a TLS key has already been derived. Deriving one here would let
        // an unauthenticated caller drive KMS traffic, and would also mint a key for an
        // app that never asked for one.
        let tls_public_key = self.tls_public_key_for_evidence(&req.app_id).await;
        let evidence = self
            .boot_service
            .get_evidence(req, &key_pair.eth_address, tls_public_key)
            .await?;
        Ok(Response::new(evidence))
    }

    async fn start_app(
        &self,
        request: Request<StartAppRequest>,
    ) -> Result<Response<StartAppResponse>, Status> {
        // Signature validation is handled by AuthLayer
        // Get signer address before consuming request
        info!("Calling StartApp");
        debug!("Request: {:?}", request);
        let signer = auth_layer::get_signer_address(&request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();

        // Get deployer address (signer EVM address)
        // If no signer (auth disabled), use a default placeholder
        let deployer = signer
            .clone()
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

        // Encrypted data volume key, derived from KMS under the "fde" namespace.
        // Built here (the RPC layer owns the KMS client) but awaited inside the
        // start task, so a slow KMS round trip delays the task, never this RPC.
        // No KMS configured → None → the app runs on a plain directory (loudly).
        let volume_key: Option<boot::VolumeKeyFut> =
            if self.kms_client.read().await.is_some() && !req_inner.measure_only {
                let kms = self.kms_client.clone();
                let keys = self.app_key_service.clone();
                let id = app_id.clone();
                Some(Box::pin(async move {
                    kms_derive_with(&kms, &keys, &id, boot::volume::FDE_MATERIAL)
                        .await
                        .map_err(|e| e.message().to_string())
                }))
            } else {
                None
            };

        // Start the app with deployer address
        let response = self
            .boot_service
            .clone()
            .start_app(req_inner, deployer.clone(), volume_key)
            .await?;

        // Derive the app's TLS identity now rather than waiting for it to be asked for.
        //
        // The rule is one sentence — the key exists as soon as the app runs — and it holds
        // for both key sources, which matters: a verifier reading "no TLS key" out of
        // evidence must not have to wonder whether it means "none" or "not fetched yet".
        //
        // Waiting is not an unlucky race but the normal case. Deployment goes start → register
        // on chain → the app fetches its certificate, and a registry event is exactly what
        // makes tappscan re-verify — so it would fetch evidence in the gap, record "no TLS
        // key", and keep saying so until its hourly backstop.
        //
        // Doing it here rather than in GetEvidence keeps it behind the owner's signature.
        // GetEvidence is unauthenticated, and deriving there would let anyone drive KMS
        // traffic, and mint keys for apps that never wanted one.
        //
        // Best effort: a KMS-sourced key needs the app registered on chain and the cluster
        // reachable, neither of which is true on a first deploy. Failing here would fail a
        // start that has already succeeded, so it is logged and the lazy path picks it up.
        if let Err(e) = self.tls_identity(&app_id).await {
            info!(
                app_id = %app_id,
                error = %e,
                "TLS identity not derived at start; it will be derived when first requested"
            );
        }

        // Record ownership if permission management is enabled
        // if let Some(pm) = &self.permission_manager {
        //     if let Some(signer_addr) = signer {
        //         pm.record_app_start(app_id.clone(), signer_addr.clone())
        //             .await;

        //         info!(
        //             app_id = %app_id,
        //             owner = %signer_addr,
        //             deployer = %deployer,
        //             event = "APP_OWNERSHIP_RECORDED",
        //             "App ownership recorded"
        //         );
        //     }
        // }

        Ok(Response::new(response))
    }

    async fn stop_app(
        &self,
        request: Request<StopAppRequest>,
    ) -> Result<Response<StopAppResponse>, Status> {
        // Get signer address before consuming request
        info!("Calling StopApp");
        debug!("Request: {:?}", request);
        let signer = auth_layer::get_signer_address(&request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();

        // Check ownership if permission management is enabled
        if let Some(pm) = &self.permission_manager {
            if let Some(signer_addr) = signer {
                // Check if user can manage this app
                if !pm.can_manage_app(&app_id, &signer_addr).await {
                    error!(
                        app_id = %app_id,
                        requester = %signer_addr,
                        event = "APP_STOP_AUTHORIZED",
                        "You don't have permission to stop app {}. Only the app owner or tapp owner can stop it.",
                        app_id
                    );
                    return Err(Status::permission_denied(format!(
                        "You don't have permission to stop app {}. Only the app owner or tapp owner can stop it.",
                        app_id
                    )));
                }

                info!(
                    app_id = %app_id,
                    requester = %signer_addr,
                    event = "APP_STOP_AUTHORIZED",
                    "User authorized to stop app"
                );
            }
        }

        // Stop the app
        self.boot_service.stop_app(&app_id).await?;

        // Mark app as stopped in ownership tracking
        if let Some(pm) = &self.permission_manager {
            pm.mark_app_stopped(&app_id).await;

            info!(
                app_id = %app_id,
                event = "APP_OWNERSHIP_UPDATED",
                "App marked as stopped"
            );
        }

        Ok(Response::new(StopAppResponse {
            success: true,
            message: format!("Application {} stopped successfully", app_id),
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn get_task_status(
        &self,
        request: Request<GetTaskStatusRequest>,
    ) -> Result<Response<GetTaskStatusResponse>, Status> {
        info!("Calling GetTaskStatus");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        match self.boot_service.get_task_status(&req.task_id).await {
            Some(task) => {
                let is_success = matches!(task.status, TaskStatus::Completed(_));

                Ok(Response::new(GetTaskStatusResponse {
                    success: is_success,
                    message: match &task.status {
                        TaskStatus::Pending => "Task is pending".to_string(),
                        TaskStatus::Running => "Task is running".to_string(),
                        TaskStatus::Completed(_) => "Task completed successfully".to_string(),
                        TaskStatus::Failed(err) => format!("Task failed: {}", err),
                    },
                    task_id: task.id.clone(),
                    status: task.to_proto_status() as i32,
                    result: task.to_proto_result(),
                    created_at: task.created_at,
                    updated_at: task.updated_at,
                }))
            }
            None => Ok(Response::new(GetTaskStatusResponse {
                success: false,
                message: format!("Task not found: {}", req.task_id),
                task_id: req.task_id,
                status: 0,
                result: None,
                created_at: 0,
                updated_at: 0,
            })),
        }
    }

    // DEPRECATED: Removed since we no longer store measurement history in memory
    // Only current running app info is stored in memory (app_info)
    // Complete measurement history is in TEE measurements
    async fn list_app_measurements(
        &self,
        _request: Request<ListAppMeasurementsRequest>,
    ) -> Result<Response<ListAppMeasurementsResponse>, Status> {
        Err(Status::unimplemented(
            "list_app_measurements is deprecated - use get_app_info for current running apps",
        ))
    }

    async fn get_app_key(
        &self,
        request: Request<GetAppKeyRequest>,
    ) -> Result<Response<GetAppKeyResponse>, Status> {
        info!("Calling GetAppKey");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        // Empty means "ethereum", the only kind that exists. Anything else is refused
        // rather than quietly answered with ethereum material: the field was accepted and
        // discarded for a long time, so a caller asking for "rsa" got an ethereum key and
        // no indication that its request had not been honoured.
        let key_type = if req.key_type.is_empty() {
            "ethereum"
        } else {
            &req.key_type
        };

        // Create-if-missing (same as GetEvidence): allows fetching the signer
        // address BEFORE the app starts, e.g. for on-chain pre-registration.
        // The key lives in this process's memory, so the app gets the same key
        // when it actually starts.
        let key_pair = self
            .app_key_service
            .get_app_key(&req.app_id, key_type, req.x25519)
            .await?;
        Ok(Response::new(GetAppKeyResponse {
            success: true,
            message: format!("Public key for app {}", req.app_id),
            eth_address: key_pair.eth_address,
            public_key: key_pair.public_key,
            x25519_public_key: key_pair.x25519_public_key.unwrap_or_default(),
            key_source: "in-memory".to_string(),
        }))
    }

    async fn get_app_tls_cert(
        &self,
        request: Request<GetAppTlsCertRequest>,
    ) -> Result<Response<GetAppTlsCertResponse>, Status> {
        info!("Calling GetAppTlsCert");

        // Reachability is the control and AuthLayer enforces it: this method is served
        // only on the Unix socket. See MethodPermission::LocalOnly.

        let req = request.into_inner();
        if req.app_id.is_empty() {
            return Err(Status::invalid_argument("app_id cannot be empty"));
        }

        let id = self.tls_identity(&req.app_id).await?;

        tracing::warn!(
            app_id = %req.app_id,
            issuer = id.issuer,
            public_key_sha256 = %id.public_key_sha256,
            event = "TLS_CERT_RETRIEVED",
            "TLS key and certificate handed to a local caller"
        );

        Ok(Response::new(GetAppTlsCertResponse {
            success: true,
            message: format!(
                "TLS identity for {} ({} key, {} certificate)",
                tls_cert::dns_name(&req.app_id),
                id.key_source,
                id.issuer
            ),
            key_pem: id.key_pem.clone(),
            cert_pem: id.cert_pem.clone(),
            issuer: id.issuer.to_string(),
            csr_pem: id.csr_pem.clone(),
            public_key_sha256: id.public_key_sha256.clone(),
            key_source: id.key_source.to_string(),
        }))
    }

    async fn get_app_secret_key(
        &self,
        request: Request<GetAppSecretKeyRequest>,
    ) -> Result<Response<GetAppSecretKeyResponse>, Status> {
        info!("Calling GetAppSecretKey");
        debug!("Request: {:?}", request);
        // Reachability is the control and AuthLayer enforces it: this method is served
        // only on the Unix socket. See MethodPermission::LocalOnly.
        let remote_addr = request.remote_addr();
        let source_type = "unix-socket";

        // Get signer address from signature (handled by AuthLayer)
        // let signer = auth_layer::get_signer_address(&request);
        let req = request.into_inner();
        let mut key_type = "ethereum".to_string();
        if !req.key_type.is_empty() {
            key_type = req.key_type;
        }

        // // SECURITY: Check app ownership
        // if let Some(pm) = &self.permission_manager {
        //     if let Some(signer_addr) = &signer {
        //         if !pm.can_manage_app(&req.app_id, signer_addr).await {
        //             tracing::error!(
        //                 app_id = %req.app_id,
        //                 signer = %signer_addr,
        //                 remote_addr = ?remote_addr,
        //                 event = "SECRET_KEY_ACCESS_DENIED",
        //                 reason = "not app owner or tapp owner",
        //                 "Permission denied: only app owner or tapp owner can access secret key"
        //             );

        //             return Err(Status::permission_denied(
        //                 "Only the app owner or tapp owner can access the app's secret key",
        //             ));
        //         }
        //     }
        // }

        // Get the app info to get compose_hash, volumes_hash, deployer
        let app_info = self
            .boot_service
            .get_app_info(&req.app_id)
            .await?
            .ok_or_else(|| {
                tracing::warn!(
                    app_id = %req.app_id,
                    event = "SECRET_KEY_ACCESS_DENIED",
                    reason = "app not found",
                    "App not found"
                );
                Status::not_found(format!("App {} not found", req.app_id))
            })?;

        // SECURITY: Log all private key access attempts
        tracing::warn!(
            app_id = %req.app_id,
            remote_addr = ?remote_addr,
            source_type = source_type,
            event = "SECRET_KEY_ACCESS",
            timestamp = %chrono::Utc::now(),
            "Private key access attempt from allowed source"
        );

        // Create base measurement for this operation
        let base_measurement = boot::AppMeasurement {
            app_id: req.app_id.clone(),
            operation: measurement_service::OPERATION_NAME_GET_APP_SECRET_KEY.to_string(),
            result: String::new(),
            error: None,
            compose_hash: app_info.compose_content.hash.clone(),
            volumes_hash: app_info.mount_files.hash.clone(),
            image_hash: app_info.compose_content.image_hash.clone(),
            deployer: app_info.owner.clone(),
            timestamp: utils::current_timestamp(),
        };

        // Try to get the key
        let result = async {
            // Get public key and address for response
            let key_response = self
                .app_key_service
                .get_app_key(&req.app_id, &key_type, req.x25519)
                .await?;

            // Get private key
            // let private_key = self.app_key_service.get_private_key(&req.app_id).await?;

            Ok::<_, crate::error::TappError>(key_response)
        }
        .await;

        // Mark measurement as success or failure
        let final_measurement = match &result {
            Ok(_) => base_measurement.with_success(),
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Extend measurement (both success and failure)
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_GET_APP_SECRET_KEY,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement for get_app_secret_key: {}", e);
        }

        // Handle result
        match result {
            Ok(key_response) => {
                // SECURITY: Log successful retrieval
                tracing::warn!(
                    app_id = %req.app_id,
                    // signer = ?signer,
                    remote_addr = ?remote_addr,
                    source_type = source_type,
                    // accessor = signer.as_deref().unwrap_or("unknown"),
                    event = "SECRET_KEY_RETRIEVED",
                    timestamp = %chrono::Utc::now(),
                    "Private key successfully retrieved"
                );

                Ok(Response::new(GetAppSecretKeyResponse {
                    success: true,
                    message: format!("Private key for app {}", req.app_id),
                    private_key: key_response.private_key,
                    public_key: key_response.public_key,
                    eth_address: key_response.eth_address,
                    x25519_public_key: key_response.x25519_public_key.unwrap_or_default(),
                }))
            }
            Err(e) => {
                tracing::error!(
                    app_id = %req.app_id,
                    // signer = ?signer,
                    remote_addr = ?remote_addr,
                    event = "SECRET_KEY_RETRIEVAL_FAILED",
                    error = %e,
                    "Failed to retrieve private key"
                );
                Err(e.into())
            }
        }
    }

    async fn get_app_csr(
        &self,
        request: Request<GetAppCsrRequest>,
    ) -> Result<Response<GetAppCsrResponse>, Status> {
        let req = request.into_inner();
        info!(app_id = %req.app_id, domain = %req.domain, "Calling GetAppCsr");

        // Reuses the cached identity, so the request is signed by exactly the key the app
        // serves and the quote commits to — deriving separately here would open a gap
        // between what gets certified and what gets attested.
        let identity = self.tls_identity(&req.app_id).await?;
        let (_, secret) = self.tls_key_material(&req.app_id).await?;
        let csr = tls_cert::signing_request(&secret, &req.domain)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        Ok(Response::new(GetAppCsrResponse {
            success: true,
            message: format!("signing request for {}", req.domain),
            csr_pem: csr,
            public_key_sha256: format!("0x{}", identity.public_key_sha256),
            key_source: identity.key_source.to_string(),
        }))
    }

    async fn get_app_info(
        &self,
        request: Request<GetAppInfoRequest>,
    ) -> Result<Response<GetAppInfoResponse>, Status> {
        info!("Calling GetAppInfo");
        debug!("Request: {:?}", request);
        let req = request.into_inner();
        let app_id = req.app_id;

        let app_info = self.boot_service.get_app_info(&app_id).await?;

        let app_info = app_info.ok_or(TappError::InvalidParameter {
            field: "app_id".to_string(),
            reason: format!("App {} not found", app_id),
        })?;

        Ok(Response::new(GetAppInfoResponse {
            success: true,
            message: format!("App info for {}", app_id),
            app_id,
            owner: app_info.owner,
            compose_hash: app_info.compose_content.hash,
            volumes_hash: app_info.mount_files.hash.into_iter().collect(),
            image_hash: app_info.compose_content.image_hash.into_iter().collect(),
            compose_content: app_info.compose_content.content,
            // volumes_content: app_info.mount_files.content,
        }))
    }

    async fn list_apps(
        &self,
        _request: Request<ListAppsRequest>,
    ) -> Result<Response<ListAppsResponse>, Status> {
        info!("Calling ListApps");
        let apps = self
            .boot_service
            .list_apps()
            .await
            .into_iter()
            .map(|(app_id, owner, compose_hash, image_count)| AppSummary {
                app_id,
                owner,
                compose_hash,
                image_count: image_count as u32,
            })
            .collect();

        Ok(Response::new(ListAppsResponse {
            success: true,
            apps,
        }))
    }

    async fn get_tapp_info(
        &self,
        _request: Request<GetTappInfoRequest>,
    ) -> Result<Response<GetTappInfoResponse>, Status> {
        info!("Calling GetTappInfo");

        // Build logging config
        let logging_config = LoggingConfigInfo {
            level: self.config.logging.level.clone(),
            format: self.config.logging.format.clone(),
            file_path: self
                .config
                .logging
                .file_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
        };

        // Live owner state (empty = unclaimed) rather than the static config —
        // with runtime claiming the config may not carry an owner at all.
        let owner_address = match &self.permission_manager {
            Some(pm) => pm.owner_address().await.unwrap_or_default(),
            None => String::new(),
        };

        // Build server config
        let server_config = ServerConfigInfo {
            bind_address: self.config.server.bind_address.clone(),
            max_connections: self.config.server.max_connections as i32,
            request_timeout_seconds: self.config.server.request_timeout_seconds as i32,
            tls_enabled: self.config.server.tls_enabled,
            tls_cert_configured: self.config.server.tls_cert_path.is_some(),
            permission_enabled: self
                .config
                .server
                .permission
                .as_ref()
                .map(|p| p.enabled)
                .unwrap_or(false),
            owner_address,
        };

        // Build boot config
        let boot_config = BootConfigInfo {
            aa_config_path: self
                .config
                .boot
                .aa_config_path
                .as_ref()
                .cloned()
                .unwrap_or_default(),
        };

        // Runtime config (set by ClaimConfig or pre-baked) takes precedence over static config.
        let runtime = self.claimed_runtime_config.read().await;

        // KBS: prefer runtime node_urls (from claim), fall back to static config
        let live_kbs_urls = if !runtime.kbs_node_urls.is_empty() {
            runtime.kbs_node_urls.clone()
        } else {
            self.config.kbs.as_ref().map(|k| k.node_urls.clone()).unwrap_or_default()
        };
        let kbs_enabled = !live_kbs_urls.is_empty();
        let kbs_config = if kbs_enabled {
            let (timeout, cert, retry) = self.config.kbs.as_ref().map(|kbs| {
                let r = RetryConfigInfo {
                    max_retries: kbs.retry.max_retries as i32,
                    initial_delay_ms: kbs.retry.initial_delay_ms as i32,
                    max_delay_ms: kbs.retry.max_delay_ms as i32,
                };
                (kbs.timeout_seconds as i32, kbs.cert_path.is_some(), Some(r))
            }).unwrap_or((30, false, None));
            Some(KbsConfigInfo {
                node_urls: live_kbs_urls,
                timeout_seconds: timeout,
                cert_configured: cert,
                retry,
            })
        } else {
            None
        };

        // Chain: prefer runtime (from claim), fall back to static config
        let live_chain_rpc = if !runtime.chain_rpc_url.is_empty() {
            runtime.chain_rpc_url.clone()
        } else {
            self.config.chain.as_ref().map(|c| c.rpc_url.clone()).unwrap_or_default()
        };
        let live_chain_contract = if !runtime.chain_contract_address.is_empty() {
            runtime.chain_contract_address.clone()
        } else {
            self.config.chain.as_ref().map(|c| c.contract_address.clone()).unwrap_or_default()
        };
        // Trust anchors have no config.toml fallback by design — see ClaimedRuntimeConfig.
        let scan_url = runtime.scan_url.clone();
        let scan_public_key = runtime.scan_public_key.clone();
        drop(runtime);

        let chain_config = if !live_chain_rpc.is_empty() || !live_chain_contract.is_empty() {
            Some(ChainConfigInfo {
                rpc_url: live_chain_rpc,
                contract_address: live_chain_contract,
            })
        } else {
            None
        };

        // Build complete config info
        let config_info = TappConfigInfo {
            logging: Some(logging_config),
            server: Some(server_config),
            boot: Some(boot_config),
            kbs: kbs_config,
            kbs_enabled,
            chain: chain_config,
            scan_url: scan_url.clone(),
            scan_public_key: scan_public_key.clone(),
        };

        Ok(Response::new(GetTappInfoResponse {
            success: true,
            message: "TAPP configuration retrieved successfully".to_string(),
            config: Some(config_info),
            version: VERSION.to_string(),
        }))
    }

    async fn get_service_status(
        &self,
        request: Request<GetServiceStatusRequest>,
    ) -> Result<Response<GetServiceStatusResponse>, Status> {
        info!("Calling GetServiceStatus");
        debug!("Request: {:?}", request);
        use tokio::process::Command;

        let req = request.into_inner();
        let log_lines = if req.log_lines > 0 { req.log_lines } else { 50 };

        info!(log_lines = log_lines, "Processing GetServiceStatus request");

        // Determine the systemd unit name
        // Try to detect from environment or use default
        let unit_name =
            std::env::var("SYSTEMD_UNIT").unwrap_or_else(|_| "tapp-server.service".to_string());

        // Get service status using systemctl show
        let status_output = Command::new("systemctl")
            .args(&["show", &unit_name, "--no-pager"])
            .output()
            .await;

        let (active_state, sub_state, active_since_timestamp, pid) = match status_output {
            Ok(output) if output.status.success() => {
                let status_text = String::from_utf8_lossy(&output.stdout);
                let mut active_state = String::from("unknown");
                let mut sub_state = String::from("unknown");
                let mut active_since = 0i64;
                let mut main_pid = 0i32;

                for line in status_text.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        match key {
                            "ActiveState" => active_state = value.to_string(),
                            "SubState" => sub_state = value.to_string(),
                            "ActiveEnterTimestamp" => {
                                // Parse timestamp (e.g., "Mon 2024-01-06 10:30:15 UTC")
                                // For now, we'll try to get the unix timestamp
                                if let Ok(ts) = value.parse::<i64>() {
                                    active_since = ts;
                                }
                            }
                            "ActiveEnterTimestampMonotonic" => {
                                if active_since == 0 {
                                    if let Ok(ts) = value.parse::<i64>() {
                                        // Convert monotonic to unix timestamp (approximate)
                                        active_since = ts / 1_000_000; // microseconds to seconds
                                    }
                                }
                            }
                            "MainPID" => {
                                if let Ok(p) = value.parse::<i32>() {
                                    main_pid = p;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                (active_state, sub_state, active_since, main_pid)
            }
            Ok(output) => {
                let error_text = String::from_utf8_lossy(&output.stderr);
                info!(
                    unit_name = %unit_name,
                    error = %error_text,
                    "systemctl show command failed"
                );
                ("unknown".to_string(), "error".to_string(), 0, 0)
            }
            Err(e) => {
                info!(
                    unit_name = %unit_name,
                    error = %e,
                    "Failed to execute systemctl command"
                );
                ("unknown".to_string(), "not-available".to_string(), 0, 0)
            }
        };

        // Get recent logs using journalctl
        let logs_output = Command::new("journalctl")
            .args(&[
                "-u",
                &unit_name,
                "-n",
                &log_lines.to_string(),
                "--no-pager",
                "--output=short-iso",
            ])
            .output()
            .await;

        let (recent_logs, log_lines_returned) = match logs_output {
            Ok(output) if output.status.success() => {
                let logs_text = String::from_utf8_lossy(&output.stdout);
                let logs: Vec<String> = logs_text.lines().map(|s| s.to_string()).collect();
                let count = logs.len() as i32;
                (logs, count)
            }
            Ok(output) => {
                let error_text = String::from_utf8_lossy(&output.stderr);
                info!(
                    unit_name = %unit_name,
                    error = %error_text,
                    "journalctl command failed"
                );
                (
                    vec![format!("Failed to retrieve logs: {}", error_text.trim())],
                    0,
                )
            }
            Err(e) => {
                info!(
                    unit_name = %unit_name,
                    error = %e,
                    "Failed to execute journalctl command"
                );
                (vec![format!("journalctl command not available: {}", e)], 0)
            }
        };

        Ok(Response::new(GetServiceStatusResponse {
            success: true,
            message: format!("Service status for {}", unit_name),
            unit_name,
            active_state,
            sub_state,
            active_since_timestamp,
            pid,
            recent_logs,
            log_lines_returned,
            timestamp: crate::utils::current_timestamp(),
            version: VERSION.to_string(),
        }))
    }

    async fn get_service_logs(
        &self,
        request: Request<GetServiceLogsRequest>,
    ) -> Result<Response<GetServiceLogsResponse>, Status> {
        info!("Calling GetServiceLogs");
        debug!("Request: {:?}", request);
        let req = request.into_inner();
        let response = self.logs_service.get_logs(req).await?;
        Ok(Response::new(response))
    }

    async fn get_app_logs(
        &self,
        request: Request<GetAppLogsRequest>,
    ) -> Result<Response<GetAppLogsResponse>, Status> {
        info!("Calling GetAppLogs");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        let service_name = if req.service_name.is_empty() {
            None
        } else {
            Some(req.service_name.as_str())
        };

        let content = self
            .boot_service
            .get_app_logs(&req.app_id, req.lines, service_name)
            .await?;

        let total_lines = content.lines().count() as i32;

        Ok(Response::new(GetAppLogsResponse {
            success: true,
            message: format!("Retrieved {} lines from app {}", total_lines, req.app_id),
            content,
            total_lines,
        }))
    }

    // ============================================================================
    // Permission Management Methods
    // ============================================================================

    async fn claim_config(
        &self,
        request: Request<ClaimConfigRequest>,
    ) -> Result<Response<ClaimConfigResponse>, Status> {
        info!("Calling ClaimConfig");

        // The claimer is whoever signed the request (validated by AuthLayer)
        let signer = auth_layer::get_signer_address(&request)
            .ok_or_else(|| Status::unauthenticated("Signer address not found"))?;
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // First-come-first-served, exactly once
        let owner = pm.claim_owner(&signer).await.map_err(|current| {
            Status::already_exists(format!("Tapp already owned by {}", current))
        })?;

        // Reject an unknown value rather than falling back: this decides whether the
        // attested TLS key survives a restart, and a typo silently becoming "local" is
        // exactly the kind of thing nobody notices until a pin breaks.
        let tls_key_source = match req.tls_key_source.as_str() {
            "" => self.config.server.tls_key_source,
            "local" => config::TlsKeySource::Local,
            "kms" => config::TlsKeySource::Kms,
            other => {
                pm.rollback_claim().await;
                return Err(Status::invalid_argument(format!(
                    "tls_key_source must be \"local\" or \"kms\", got {:?}",
                    other
                )));
            }
        };

        // Same reasoning as tls_key_source: reject rather than fall back, because a
        // half-configured trust anchor is not a lesser configuration, it is a wrong one.
        let scan = match validate_scan_anchor(&req.scan_url, &req.scan_public_key) {
            Ok(v) => v,
            Err(e) => {
                pm.rollback_claim().await;
                return Err(Status::invalid_argument(e));
            }
        };
        let (scan_url, scan_public_key) = scan.unwrap_or_default();

        // Extend runtime measurement — includes the full config so verifiers
        // see owner + chain + kbs in one event. On failure the claim is rolled
        // back so the tapp stays claimable.
        // The cluster the node will actually use, not just what this request named: the KMS
        // client is only replaced when the request supplies urls, so a claim that supplies
        // none leaves the node serving from config.toml. Recording the request verbatim
        // measured `kbs_node_urls: []` on a node using four of them — an event log stating
        // something false about the node it describes. Same fix as UpdateTrustAnchors.
        let effective_kbs = if req.kbs_node_urls.is_empty() {
            self.config
                .kbs
                .as_ref()
                .map(|k| k.node_urls.clone())
                .unwrap_or_default()
        } else {
            req.kbs_node_urls.clone()
        };

        let timestamp = utils::current_timestamp();
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_CLAIM_CONFIG,
            "owner": owner,
            "chain_rpc_url": req.chain_rpc_url,
            "chain_contract_address": req.chain_contract_address,
            "kbs_node_urls": effective_kbs,
            "tls_key_source": tls_key_source.as_str(),
            "scan_url": scan_url,
            "scan_public_key": scan_public_key,
            "timestamp": timestamp
        })
        .to_string();

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_CLAIM_CONFIG,
                &measurement_data,
            )
            .await
        {
            pm.rollback_claim().await;
            return Err(Status::internal(format!(
                "Failed to extend measurement for claim: {}",
                e
            )));
        }

        // Store runtime config so get-tapp-info can show live values.
        *self.claimed_runtime_config.write().await = ClaimedRuntimeConfig {
            chain_rpc_url: req.chain_rpc_url.clone(),
            chain_contract_address: req.chain_contract_address.clone(),
            kbs_node_urls: effective_kbs.clone(),
            tls_key_source: tls_key_source.as_str().to_string(),
            scan_url: scan_url.clone(),
            scan_public_key: scan_public_key.clone(),
        };

        // Initialize or replace KMS client whenever the claim changed anything it
        // is built from: the node set OR the trust anchor. The anchor case is the
        // one that used to be dropped — with [kbs] baked into config.toml and only
        // --scan-url/--scan-pubkey claimed, the running client kept connecting
        // UNVERIFIED while the measured claim (and get-tapp-info) said otherwise.
        if !effective_kbs.is_empty() && (!req.kbs_node_urls.is_empty() || !scan_url.is_empty()) {
            info!(
                nodes = effective_kbs.len(),
                anchored = !scan_url.is_empty(),
                "Initializing KMS client from ClaimConfig"
            );
            *self.kms_client.write().await = Some(kms_client_with_anchor(
                effective_kbs.clone(),
                &Default::default(),
                &scan_url,
                &scan_public_key,
            ));
        }

        // Persist so a process restart within this boot cannot reopen the claim.
        if let Err(e) = pm.persist_owner().await {
            tracing::warn!(error = %e, "Failed to persist claimed owner");
        }

        info!(
            owner = %owner,
            chain_contract = %req.chain_contract_address,
            kbs_nodes = req.kbs_node_urls.len(),
            event = "CONFIG_CLAIMED",
            "Tapp config claimed and measurement extended"
        );

        Ok(Response::new(ClaimConfigResponse {
            success: true,
            message: format!("Tapp config claimed by {}", owner),
            owner_address: owner,
            timestamp,
        }))
    }

    async fn update_trust_anchors(
        &self,
        request: Request<UpdateTrustAnchorsRequest>,
    ) -> Result<Response<UpdateTrustAnchorsResponse>, Status> {
        info!("Calling UpdateTrustAnchors");
        let req = request.into_inner();

        let scan = validate_scan_anchor(&req.scan_url, &req.scan_public_key)
            .map_err(Status::invalid_argument)?;

        // Refuse a call that would do nothing rather than emitting a measurement event
        // saying nothing changed. An empty request is a mistake — most likely a caller
        // that meant to clear something and cannot, since empty means "leave alone".
        if scan.is_none() && req.kbs_node_urls.is_empty() {
            return Err(Status::invalid_argument(
                "nothing to update: give --kbs-urls, or --scan-url with --scan-pubkey",
            ));
        }

        // Compute the resulting state before touching anything, so the event and the
        // applied config cannot disagree, and so a measurement failure leaves the tapp
        // exactly as it was.
        let resulting = {
            let current = self.claimed_runtime_config.read().await;
            let (scan_url, scan_public_key) = match &scan {
                Some((u, p)) => (u.clone(), p.clone()),
                None => (current.scan_url.clone(), current.scan_public_key.clone()),
            };
            // Fall back to config.toml exactly as GetTappInfo does. Reading only the claimed
            // value would measure `kbs_node_urls: []` on a node that is really using four
            // nodes from config.toml — an event log stating something false about the node
            // it describes, which is worse than not recording it. Found on a live node:
            // the claim had supplied no --kbs-urls, so the runtime value was empty while
            // the server was serving requests from the baked-in cluster the whole time.
            let kbs_node_urls = if !req.kbs_node_urls.is_empty() {
                req.kbs_node_urls.clone()
            } else if !current.kbs_node_urls.is_empty() {
                current.kbs_node_urls.clone()
            } else {
                self.config
                    .kbs
                    .as_ref()
                    .map(|k| k.node_urls.clone())
                    .unwrap_or_default()
            };
            ClaimedRuntimeConfig {
                chain_rpc_url: current.chain_rpc_url.clone(),
                chain_contract_address: current.chain_contract_address.clone(),
                tls_key_source: current.tls_key_source.clone(),
                kbs_node_urls,
                scan_url,
                scan_public_key,
            }
        };

        // The event carries the resulting anchors in full, not the delta. That is what lets
        // a verifier read the newest event of this kind and stop, instead of replaying every
        // update since boot to work out the current state.
        let timestamp = utils::current_timestamp();
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_UPDATE_TRUST_ANCHORS,
            "kbs_node_urls": resulting.kbs_node_urls,
            "scan_url": resulting.scan_url,
            "scan_public_key": resulting.scan_public_key,
            "timestamp": timestamp
        })
        .to_string();

        // Measure first, apply second. An unmeasured change to a trust anchor is the one
        // outcome that must not happen: it is the property that makes these mutable at all.
        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_UPDATE_TRUST_ANCHORS,
                &measurement_data,
            )
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "Failed to extend measurement for trust anchor update, nothing applied: {}",
                    e
                ))
            })?;

        let kbs_changed = !req.kbs_node_urls.is_empty();
        *self.claimed_runtime_config.write().await = resulting.clone();

        // Replace the KMS client so the new cluster takes effect on the next request
        // rather than at the next restart.
        // Rebuilt when EITHER anchor moved. Rebuilding only for the cluster would leave
        // a node that changed verifier still checking against the old one until it
        // restarted — a trust anchor that has visibly been replaced but is not yet in use.
        if kbs_changed || scan.is_some() {
            info!(
                nodes = resulting.kbs_node_urls.len(),
                scan = %resulting.scan_url,
                "Replacing KMS client from UpdateTrustAnchors"
            );
            *self.kms_client.write().await = Some(kms_client_with_anchor(
                resulting.kbs_node_urls.clone(),
                &Default::default(),
                &resulting.scan_url,
                &resulting.scan_public_key,
            ));
        }

        info!(
            kbs_nodes = resulting.kbs_node_urls.len(),
            scan_url = %resulting.scan_url,
            event = "TRUST_ANCHORS_UPDATED",
            "Trust anchors updated and measurement extended"
        );

        Ok(Response::new(UpdateTrustAnchorsResponse {
            success: true,
            message: "Trust anchors updated".to_string(),
            kbs_node_urls: resulting.kbs_node_urls,
            scan_url: resulting.scan_url,
            scan_public_key: resulting.scan_public_key,
            timestamp,
        }))
    }

    async fn add_to_whitelist(
        &self,
        request: Request<AddToWhitelistRequest>,
    ) -> Result<Response<AddToWhitelistResponse>, Status> {
        info!("Calling AddToWhitelist");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Add address to whitelist
        pm.add_to_whitelist(req.evm_address.clone())
            .await
            .map_err(|e| Status::internal(format!("Failed to add to whitelist: {}", e)))?;

        // Extend runtime measurement for this security-critical operation
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_ADD_TO_WHITELIST,
            "address": req.evm_address,
            "timestamp": utils::current_timestamp()
        })
        .to_string();

        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_ADD_TO_WHITELIST,
                &measurement_data,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to extend measurement: {}", e)))?;

        info!(
            address = %req.evm_address,
            event = "WHITELIST_ADDED",
            "Address added to whitelist and measurement extended"
        );

        Ok(Response::new(AddToWhitelistResponse {
            success: true,
            message: format!("Address {} added to whitelist", req.evm_address),
        }))
    }

    async fn remove_from_whitelist(
        &self,
        request: Request<RemoveFromWhitelistRequest>,
    ) -> Result<Response<RemoveFromWhitelistResponse>, Status> {
        info!("Calling RemoveFromWhitelist");
        debug!("Request: {:?}", request);
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Remove address from whitelist
        pm.remove_from_whitelist(&req.evm_address)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove from whitelist: {}", e)))?;

        // Extend runtime measurement for this security-critical operation
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_REMOVE_FROM_WHITELIST,
            "address": req.evm_address,
            "timestamp": utils::current_timestamp()
        })
        .to_string();

        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_REMOVE_FROM_WHITELIST,
                &measurement_data,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to extend measurement: {}", e)))?;

        info!(
            address = %req.evm_address,
            event = "WHITELIST_REMOVED",
            "Address removed from whitelist and measurement extended"
        );

        Ok(Response::new(RemoveFromWhitelistResponse {
            success: true,
            message: format!("Address {} removed from whitelist", req.evm_address),
        }))
    }

    async fn list_whitelist(
        &self,
        _request: Request<ListWhitelistRequest>,
    ) -> Result<Response<ListWhitelistResponse>, Status> {
        info!("Calling ListWhitelist");
        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        let addresses = pm.list_whitelist().await;

        Ok(Response::new(ListWhitelistResponse {
            success: true,
            message: format!("Found {} whitelisted address(es)", addresses.len()),
            addresses,
        }))
    }

    async fn get_app_ownership(
        &self,
        request: Request<GetAppOwnershipRequest>,
    ) -> Result<Response<GetAppOwnershipResponse>, Status> {
        info!("Calling GetAppOwnership");
        debug!("Request: {:?}", request);
        // Get signer address before consuming request
        let signer = auth_layer::get_signer_address(&request)
            .ok_or_else(|| Status::unauthenticated("Signer address not found"))?;

        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Check if user can view this app's ownership
        // Owner can view all, others can only view if they can manage the app
        if !pm.can_manage_app(&req.app_id, &signer).await && !pm.is_owner(&signer).await {
            return Err(Status::permission_denied(
                "You don't have permission to view this app's ownership",
            ));
        }

        let ownership = pm.get_app_ownership(&req.app_id).await;

        match ownership {
            Some(own) => Ok(Response::new(GetAppOwnershipResponse {
                success: true,
                message: format!("Ownership info for app {}", req.app_id),
                ownership: Some(AppOwnershipInfo {
                    app_id: own.app_id,
                    owner_address: own.owner_address,
                    started_at: own.started_at,
                    status: match own.status {
                        permission::AppStatus::Active => proto::AppStatus::Active.into(),
                        permission::AppStatus::Stopped => proto::AppStatus::Stopped.into(),
                    },
                    stopped_at: own.stopped_at.unwrap_or(0),
                }),
            })),
            None => Err(Status::not_found(format!("App {} not found", req.app_id))),
        }
    }

    async fn list_all_ownerships(
        &self,
        _request: Request<ListAllOwnershipsRequest>,
    ) -> Result<Response<ListAllOwnershipsResponse>, Status> {
        info!("Calling ListAllOwnerships");
        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        let ownerships_list = pm.list_all_ownerships().await;

        let ownerships: Vec<AppOwnershipInfo> = ownerships_list
            .into_iter()
            .map(|own| AppOwnershipInfo {
                app_id: own.app_id,
                owner_address: own.owner_address,
                started_at: own.started_at,
                status: match own.status {
                    permission::AppStatus::Active => proto::AppStatus::Active.into(),
                    permission::AppStatus::Stopped => proto::AppStatus::Stopped.into(),
                },
                stopped_at: own.stopped_at.unwrap_or(0),
            })
            .collect();

        Ok(Response::new(ListAllOwnershipsResponse {
            success: true,
            message: format!("Found {} app ownership(s)", ownerships.len()),
            ownerships,
        }))
    }

    async fn withdraw_balance(
        &self,
        request: Request<WithdrawBalanceRequest>,
    ) -> Result<Response<WithdrawBalanceResponse>, Status> {
        info!("Calling WithdrawBalance");
        debug!("Request: {:?}", request);
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let app_id = &req.app_id;

        // Get app private key
        let private_key = self
            .app_key_service
            .get_private_key(app_id)
            .await
            .map_err(|e| Status::not_found(format!("App key not found: {}", e)))?;

        // Determine recipient
        let recipient = if req.recipient.is_empty() {
            match self.permission_manager.as_ref() {
                Some(pm) => pm
                    .owner_address()
                    .await
                    .ok_or_else(|| Status::failed_precondition("TAPP owner not claimed"))?,
                None => return Err(Status::internal("TAPP owner not configured")),
            }
        } else {
            req.recipient.clone()
        };

        // Execute withdrawal
        let result = balance_withdrawal::withdraw_balance(
            &private_key,
            &req.rpc_url,
            req.chain_id,
            &recipient,
        )
        .await
        .map_err(|e| Status::internal(format!("Withdrawal failed: {}", e)))?;

        // Record measurement
        let measurement = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_WITHDRAW_BALANCE,
            "app_id": app_id,
            "from_address": result.from_address,
            "to_address": result.to_address,
            "amount": result.amount,
            "transaction_hash": result.transaction_hash,
            "chain_id": req.chain_id,
            "signer": signer,
            "timestamp": chrono::Utc::now().timestamp(),
        });

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_WITHDRAW_BALANCE,
                &measurement.to_string(),
            )
            .await
        {
            tracing::warn!(error = ?e, "Failed to record withdrawal measurement");
        }

        tracing::info!(
            app_id = %app_id,
            tx_hash = %result.transaction_hash,
            amount = %result.amount,
            event = "WITHDRAW_BALANCE_SUCCESS",
            "Balance withdrawal successful"
        );

        Ok(Response::new(WithdrawBalanceResponse {
            success: true,
            message: "Withdrawal successful".to_string(),
            transaction_hash: result.transaction_hash,
            from_address: result.from_address,
            to_address: result.to_address,
            amount: result.amount,
            gas_used: result.gas_used,
            gas_price: result.gas_price.parse().unwrap_or(0),
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn docker_login(
        &self,
        request: Request<DockerLoginRequest>,
    ) -> Result<Response<DockerLoginResponse>, Status> {
        info!("Calling DockerLogin");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let registry = req.registry.clone();
        let username = req.username.clone();

        // Execute docker login
        self.boot_service
            .docker_login(&registry, &username, &req.password)
            .await?;

        // Determine actual registry for response
        let actual_registry = if registry.is_empty() {
            "docker.io".to_string()
        } else {
            registry
        };

        // Record measurement
        let measurement = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_DOCKER_LOGIN,
            "registry": actual_registry.clone(),
            "username": username.clone(),
            "signer": signer.clone(),
            "timestamp": chrono::Utc::now().timestamp(),
        });

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_DOCKER_LOGIN,
                &measurement.to_string(),
            )
            .await
        {
            tracing::warn!(error = ?e, "Failed to record docker login measurement");
        }

        tracing::info!(
            registry = %actual_registry,
            username = %username,
            signer = %signer.unwrap_or_default(),
            event = "DOCKER_LOGIN_SUCCESS",
            "Docker login successful"
        );

        Ok(Response::new(DockerLoginResponse {
            success: true,
            message: format!("Successfully logged into {}", actual_registry),
            registry: actual_registry,
            username,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn docker_logout(
        &self,
        request: Request<DockerLogoutRequest>,
    ) -> Result<Response<DockerLogoutResponse>, Status> {
        info!("Calling DockerLogout");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let registry = req.registry.clone();

        // Execute docker logout
        self.boot_service.docker_logout(&registry).await?;

        // Determine actual registry for response
        let actual_registry = if registry.is_empty() {
            "docker.io".to_string()
        } else {
            registry
        };

        // Record measurement
        let measurement = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_DOCKER_LOGOUT,
            "registry": actual_registry.clone(),
            "signer": signer.clone(),
            "timestamp": chrono::Utc::now().timestamp(),
        });

        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_DOCKER_LOGOUT,
                &measurement.to_string(),
            )
            .await
        {
            tracing::warn!(error = ?e, "Failed to record docker logout measurement");
        }

        tracing::info!(
            registry = %actual_registry,
            signer = %signer.unwrap_or_default(),
            event = "DOCKER_LOGOUT_SUCCESS",
            "Docker logout successful"
        );

        Ok(Response::new(DockerLogoutResponse {
            success: true,
            message: format!("Successfully logged out from {}", actual_registry),
            registry: actual_registry,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn stop_service(
        &self,
        request: Request<StopServiceRequest>,
    ) -> Result<Response<StopServiceResponse>, Status> {
        // Get signer address before consuming request
        info!("Calling StopService");
        debug!("Request: {:?}", request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();
        let service_name = req_inner.service_name.clone();

        // Stop the service
        self.boot_service
            .stop_service(&app_id, &service_name)
            .await?;

        Ok(Response::new(StopServiceResponse {
            success: true,
            message: format!("Service {}.{} stopped successfully", app_id, service_name),
            app_id,
            service_name,
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn start_service(
        &self,
        request: Request<StartServiceRequest>,
    ) -> Result<Response<StartServiceResponse>, Status> {
        // Signature validation is handled by AuthLayer
        // Get signer address before consuming request
        info!("Calling StartService");
        debug!("Request: {:?}", request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();
        let service_name = req_inner.service_name.clone();
        let pull_image = req_inner.pull_image;

        // Start the service (returns task_id for async operation)
        let task_id = self
            .boot_service
            .clone()
            .start_service(app_id.clone(), service_name.clone(), pull_image)
            .await?;

        Ok(Response::new(StartServiceResponse {
            success: true,
            message: format!(
                "Task created successfully for starting service {}.{} Use task_id to check status.",
                app_id, service_name
            ),
            task_id,
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn prune_images(
        &self,
        request: Request<PruneImagesRequest>,
    ) -> Result<Response<PruneImagesResponse>, Status> {
        info!("Calling PruneImages");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let all = req.all;
        // Execute docker image prune
        let result = self.boot_service.prune_images(all).await?;

        tracing::info!(
            images_deleted = result.images_deleted,
            space_reclaimed = result.space_reclaimed,
            signer = %signer.unwrap_or_default(),
            event = "DOCKER_PRUNE_IMAGES_SUCCESS",
            "Docker image prune successful"
        );

        Ok(Response::new(PruneImagesResponse {
            success: true,
            message: format!(
                "Pruned {} images, reclaimed {} bytes",
                result.images_deleted, result.space_reclaimed
            ),
            images_deleted: result.images_deleted,
            space_reclaimed: result.space_reclaimed,
            deleted_images: result.deleted_images,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn get_app_container_status(
        &self,
        request: Request<GetAppContainerStatusRequest>,
    ) -> Result<Response<GetAppContainerStatusResponse>, Status> {
        info!("Calling GetAppContainerStatus");
        let signer = auth_layer::get_signer_address(&request);

        let req = request.into_inner();
        let app_id = req.app_id.clone();

        let _ = self
            .boot_service
            .get_app_info(&app_id)
            .await?
            .ok_or_else(|| {
                tracing::warn!(
                    app_id = %app_id,
                    event = "SECRET_KEY_ACCESS_DENIED",
                    reason = "app not found",
                    "App not found"
                );
                Status::not_found(format!("App {} not found", app_id))
            })?;

        // Get container status (app may not exist, but we still return status)
        let app_status = self.boot_service.get_app_container_status(&app_id).await?;

        // Convert to proto response
        let containers: Vec<proto::ContainerStatus> = app_status
            .containers
            .into_iter()
            .map(|c| proto::ContainerStatus {
                name: c.name,
                state: c.state,
                health: c.health.unwrap_or_default(),
                ports: c.ports,
            })
            .collect();

        let container_count = app_status.container_count as i32;
        let running = app_status.running;
        let started_at = app_status.started_at.unwrap_or(0);

        tracing::info!(
            app_id = %app_id,
            container_count = container_count,
            running = running,
            containers_len = containers.len(),
            started_at = started_at,
            signer = %signer.unwrap_or_default(),
            event = "GET_APP_CONTAINER_STATUS_SUCCESS",
            "Get app container status successful"
        );

        let response = GetAppContainerStatusResponse {
            success: true,
            message: format!(
                "App {} has {} containers, running: {}",
                app_id, container_count, running
            ),
            app_id: app_id.clone(),
            running,
            container_count,
            containers,
            started_at,
            timestamp: chrono::Utc::now().timestamp(),
        };

        // Debug: log response fields
        tracing::debug!(
            app_id = %response.app_id,
            running = response.running,
            container_count = response.container_count,
            containers_count = response.containers.len(),
            started_at = response.started_at,
            "Response fields set"
        );

        Ok(Response::new(response))
    }

    async fn get_secret_resource(
        &self,
        request: Request<GetSecretResourceRequest>,
    ) -> Result<Response<GetSecretResourceResponse>, Status> {
        info!("Calling GetSecretResource");

        // Reachability is the control and AuthLayer enforces it: this method is served
        // only on the Unix socket. See MethodPermission::LocalOnly.

        let req = request.into_inner();
        let app_id = &req.app_id;

        let secret = self.kms_derive(app_id, &req.material).await?;

        self.measure_secret_resource(app_id, &req.material, true).await;

        info!(app_id = %app_id, "GetSecretResource succeeded");

        Ok(Response::new(GetSecretResourceResponse {
            success: true,
            message: format!("Secret resource retrieved for app {}", app_id),
            secret,
        }))
    }
}

/// Initialize tracing based on configuration
/// Delete the oldest `{prefix}.*` daily log files so at most `max_files - 1`
/// remain (the appender then creates/opens today's file, bringing the total
/// back to `max_files`). Filenames embed the date (`prefix.yyyy-MM-dd`), so
/// lexicographic order == chronological order. Best-effort: IO errors are
/// ignored — logging setup must not fail because a stale file can't be removed.
fn prune_old_log_files(directory: &std::path::Path, prefix: &str, max_files: usize) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let wanted = format!("{}.", prefix);
    let mut files: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with(&wanted))
        .collect();
    if files.len() < max_files {
        return;
    }
    files.sort();
    for name in &files[..files.len() - (max_files - 1)] {
        let _ = std::fs::remove_file(directory.join(name));
    }
}

pub fn init_tracing(config: &config::LoggingConfig) -> TappResult<()> {
    use tracing_subscriber::{
        fmt::{self, format::FmtSpan},
        layer::SubscriberExt,
        util::SubscriberInitExt,
        EnvFilter, Layer,
    };

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.level))
        .map_err(|e| error::ConfigError::InvalidValue {
            field: "logging.level".to_string(),
            reason: format!("Invalid log level: {}", e),
        })?;

    let stdout_layer = match config.format.as_str() {
        "json" => fmt::layer()
            .json()
            .with_writer(std::io::stdout)
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        "pretty" => fmt::layer()
            .pretty()
            .with_writer(std::io::stdout)
            .with_ansi(true)
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        _ => {
            return Err(error::ConfigError::InvalidValue {
                field: "logging.format".to_string(),
                reason: format!("Unsupported log format: {}", config.format),
            }
            .into());
        }
    };

    if let Some(file_path) = &config.file_path {
        use tracing_appender::rolling::{RollingFileAppender, Rotation};

        let path = std::path::Path::new(file_path);

        let (directory, file_name_prefix) = if file_path.to_string_lossy().ends_with('/') {
            (path, "app")
        } else if path.extension().is_some() {
            let directory = path.parent().unwrap_or(std::path::Path::new("."));
            let file_name_prefix = path.file_stem().and_then(|n| n.to_str()).unwrap_or("app");
            (directory, file_name_prefix)
        } else {
            let directory = path.parent().unwrap_or(std::path::Path::new("."));
            let file_name_prefix = path.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            (directory, file_name_prefix)
        };

        std::fs::create_dir_all(directory).map_err(|e| error::ConfigError::InvalidValue {
            field: "logging.file_path".to_string(),
            reason: format!("Cannot create log directory: {}", e),
        })?;

        // Keep at most `max_log_files` daily files — without a retention cap the
        // rotated files accumulate forever, which on RAM-rootfs CVM images means
        // unbounded RAM growth (issue #23).
        //
        // tracing-appender only prunes inside refresh_writer, i.e. when the date
        // rolls over WHILE the process is running — files left by previous runs
        // survive until the first in-process midnight, and a process that never
        // lives past midnight never prunes at all. Prune at startup ourselves.
        prune_old_log_files(directory, file_name_prefix, config.max_log_files.max(1));

        let file_appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(file_name_prefix)
            .max_log_files(config.max_log_files.max(1))
            .build(directory)
            .map_err(|e| error::ConfigError::InvalidValue {
                field: "logging.file_path".to_string(),
                reason: format!("Cannot create log appender: {}", e),
            })?;

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        std::mem::forget(_guard);

        let file_layer = match config.format.as_str() {
            "json" => fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE)
                .boxed(),
            "pretty" => fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE)
                .boxed(),
            _ => unreachable!(),
        };

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "0x8745d897b66f77d711afa62f282b6b540236e72c3d5d1a2b1e18875f1fc33298";

    #[test]
    fn both_anchor_fields_empty_means_leave_alone() {
        assert_eq!(validate_scan_anchor("", ""), Ok(None));
    }

    #[test]
    fn a_url_without_a_pin_is_refused_rather_than_accepted_unauthenticated() {
        // The failure this prevents: an operator sets only the URL, the channel is then
        // unauthenticated, and the verdict it carries is rewritable by anyone on the path
        // — while the config reads as though a verifier is configured.
        assert!(validate_scan_anchor("https://scan.example", "").is_err());
        assert!(validate_scan_anchor("", PIN).is_err());
    }

    #[test]
    fn plaintext_is_refused_because_a_pin_needs_a_channel_to_bind_to() {
        assert!(validate_scan_anchor("http://scan.example", PIN).is_err());
    }

    #[test]
    fn a_pin_that_is_not_a_sha256_is_refused_rather_than_truncated() {
        for bad in ["0xdeadbeef", "not-hex-at-all", &"0x".to_string()] {
            assert!(
                validate_scan_anchor("https://scan.example", bad).is_err(),
                "accepted {:?}",
                bad
            );
        }
        // 64 hex chars but one non-hex character — length alone is not enough.
        let almost = format!("0x{}z", &PIN[2..65]);
        assert!(validate_scan_anchor("https://scan.example", &almost).is_err());
    }

    #[test]
    fn an_accepted_pin_is_normalised_so_comparisons_cannot_miss_on_case_or_prefix() {
        let upper = format!("0X{}", PIN[2..].to_uppercase());
        let bare = &PIN[2..];
        let expected = Some(("https://scan.example".to_string(), PIN.to_string()));
        assert_eq!(validate_scan_anchor("https://scan.example", bare), Ok(expected.clone()));
        // A "0X" prefix is not stripped by strip_prefix("0x"), so it lands in the hex part
        // and is rejected on length — documented here so the behaviour is deliberate.
        assert!(validate_scan_anchor("https://scan.example", &upper).is_err());
        assert_eq!(
            validate_scan_anchor("https://scan.example", &PIN.to_uppercase().replace("0X", "0x")),
            Ok(expected)
        );
    }

    #[test]
    fn test_prune_old_log_files() {
        let dir = std::env::temp_dir().join(format!("tapp-prune-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 10 accumulated daily files + an unrelated file that must survive
        for d in 1..=10 {
            std::fs::write(dir.join(format!("app.2026-07-{:02}", d)), "old").unwrap();
        }
        std::fs::write(dir.join("other.txt"), "keep").unwrap();

        prune_old_log_files(&dir, "app", 7);

        let mut files: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        // newest 6 kept (appender's new file for today makes 7), oldest 4 gone
        assert_eq!(
            files,
            vec![
                "app.2026-07-05",
                "app.2026-07-06",
                "app.2026-07-07",
                "app.2026-07-08",
                "app.2026-07-09",
                "app.2026-07-10",
                "other.txt"
            ]
        );

        // fewer files than the cap -> untouched
        prune_old_log_files(&dir, "app", 7);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 7);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_validate_app_id() {
        assert!(utils::validate_app_id("my-app"));
        assert!(utils::validate_app_id("app_123"));
        assert!(utils::validate_app_id("test-application-1"));

        assert!(!utils::validate_app_id("ab")); // too short
        assert!(!utils::validate_app_id("a".repeat(65).as_str())); // too long
        assert!(!utils::validate_app_id("app@123")); // invalid character
        assert!(!utils::validate_app_id("app space")); // contains space
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"hello world";
        let hash = utils::sha256_hex(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(utils::format_bytes(0), "0 B");
        assert_eq!(utils::format_bytes(1024), "1.00 KB");
        assert_eq!(utils::format_bytes(1536), "1.50 KB");
        assert_eq!(utils::format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_pad_to_length() {
        let data = b"hello";
        let padded = utils::pad_to_length(data, 10);
        assert_eq!(padded.len(), 10);
        assert_eq!(&padded[0..5], b"hello");
        assert_eq!(&padded[5..], &[0u8; 5]);
    }
}
