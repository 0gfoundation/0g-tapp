use crate::error::TappResult;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub const ZGEL_DOMAIN: &str = "tapp.0g.com";

// Operation names for measurements
pub const OPERATION_NAME_START_APP: &str = "start_app";
pub const OPERATION_NAME_STOP_APP: &str = "stop_app";
pub const OPERATION_NAME_GET_APP_SECRET_KEY: &str = "get_app_secret_key";
pub const OPERATION_NAME_ADD_TO_WHITELIST: &str = "add_to_whitelist";
pub const OPERATION_NAME_REMOVE_FROM_WHITELIST: &str = "remove_from_whitelist";
pub const OPERATION_NAME_WITHDRAW_BALANCE: &str = "withdraw_balance";
pub const OPERATION_NAME_DOCKER_LOGIN: &str = "docker_login";
pub const OPERATION_NAME_DOCKER_LOGOUT: &str = "docker_logout";
pub const OPERATION_NAME_STOP_SERVICE: &str = "stop_service";
pub const OPERATION_NAME_START_SERVICE: &str = "start_service";
pub const OPERATION_NAME_CLAIM_CONFIG: &str = "claim_config";
/// Each change to which KMS cluster / verifier this tapp trusts. Separate from
/// `claim_config` so a verifier can tell the original claim from a later revision, and
/// carries the resulting state in full so the newest event alone is the current answer.
pub const OPERATION_NAME_UPDATE_TRUST_ANCHORS: &str = "update_trust_anchors";
pub const OPERATION_NAME_GET_SECRET_RESOURCE: &str = "get_secret_resource";
/// Giving the node the persistent disk that /data lives on.
///
/// Measured because it is an owner action that changes what the node is — a node with no
/// /data cannot host anything, and after this one it can. But the reason it MUST be measured
/// is the distinction it records: a disk that was `formatted` means the node started from
/// nothing, while one that was `adopted` means it inherited content it did not create. That
/// content is not all protected equally. App volumes are LUKS-encrypted under KMS keys so they
/// cannot be forged — but they CAN be an older state, so adopting a stale disk rolls app data
/// back; and file logs under /data/log are protected by nothing at all, so a pre-seeded disk
/// can hand a node a fabricated history of itself.
///
/// None of that is detectable from outside if the choice goes unrecorded — the two cases look
/// identical in the evidence. With the event, a verifier reading `adopted` knows to ask where
/// that disk came from, and the append-only log means the question can always be asked later.
pub const OPERATION_NAME_PROVISION_DATA_DISK: &str = "provision_data_disk";

pub struct MeasurementService {
    aa: Arc<Mutex<AttestationAgent>>,
}

impl MeasurementService {
    pub fn new(aa: Arc<Mutex<AttestationAgent>>) -> Self {
        Self { aa }
    }

    /// Extend runtime measurement for any operation
    pub async fn extend_measurement(&self, operation_name: &str, data: &str) -> TappResult<()> {
        self.aa
            .lock()
            .await
            .extend_runtime_measurement(ZGEL_DOMAIN, operation_name, data, None)
            .await?;

        info!(
            operation = %operation_name,
            data = ?data,
            "Runtime measurement extended"
        );

        Ok(())
    }

    /// Get TEE type
    pub async fn get_tee_type(&self) -> String {
        format!("{:?}", self.aa.lock().await.get_tee_type())
    }

    /// Get evidence
    pub async fn get_evidence(&self, report_data: &[u8]) -> TappResult<Vec<u8>> {
        let evidence = self.aa.lock().await.get_evidence(report_data).await?;
        Ok(evidence)
    }
}
