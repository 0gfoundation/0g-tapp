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
/// An audit trail for an owner action, at the same level as `docker_login` — not a security
/// boundary, and it should not be read as one. `formatted` vs `adopted` records whether the
/// node started from a blank disk or took over an existing one, which is useful when
/// reconstructing what happened to a node, and that is the whole of it.
///
/// It says nothing about whether the content is trustworthy, because provenance is not what
/// makes storage trustworthy here. Everything on /data outside an app's LUKS volume is
/// host-controlled plaintext that can be rewritten at any moment, whoever created the
/// filesystem; and an app volume can be rolled back to an earlier valid state regardless of
/// how the disk arrived. What the platform does and does not promise about data at rest is
/// set out in docs/DATA_AT_REST.md.
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
