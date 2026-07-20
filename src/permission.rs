use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Permission level for operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    Owner,     // Full control (tapp owner)
    Whitelist, // Can start apps and manage own apps
    Public,    // Read-only access
}

/// App status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    Active,
    Stopped,
}

/// App ownership tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppOwnership {
    pub app_id: String,
    pub owner_address: String, // EVM address of who owns this app (who started it)
    pub started_at: i64,
    pub status: AppStatus,
    pub stopped_at: Option<i64>,
}

/// Permission manager - manages the (claimable) tapp owner, whitelist and app ownership
pub struct PermissionManager {
    /// Tapp owner EVM address. `None` = unclaimed: nobody holds Owner
    /// permission until `claim_owner` succeeds (first-come-first-served via
    /// the ClaimOwner RPC) or an owner is restored at startup (from config or
    /// the persisted claim of the current boot).
    tapp_owner_address: RwLock<Option<String>>,

    /// Where the claimed owner is persisted so a tapp-server process restart
    /// within the same boot cannot reopen the claim. Lives on tmpfs (/run) by
    /// design: cleared on VM reboot, exactly matching the RTMR lifetime.
    owner_state_path: Option<std::path::PathBuf>,

    /// Whitelist of EVM addresses allowed to start apps
    whitelist: Arc<RwLock<HashSet<String>>>,

    /// App ownership tracking: app_id -> ownership
    app_ownership: Arc<RwLock<HashMap<String, AppOwnership>>>,
}

impl PermissionManager {
    pub fn new(tapp_owner_address: Option<String>) -> Self {
        Self {
            tapp_owner_address: RwLock::new(
                tapp_owner_address.map(|a| Self::normalize_address(&a)),
            ),
            owner_state_path: None,
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            app_ownership: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Enable owner-claim persistence at `path` (see `owner_state_path`).
    pub fn with_owner_state_path(mut self, path: std::path::PathBuf) -> Self {
        self.owner_state_path = Some(path);
        self
    }

    /// Normalize EVM address (lowercase, with 0x prefix)
    pub fn normalize_address(addr: &str) -> String {
        let addr = addr.trim().to_lowercase();
        if addr.starts_with("0x") {
            addr
        } else {
            format!("0x{}", addr)
        }
    }

    /// Get permission level for an EVM address.
    /// While the tapp is unclaimed, nobody has Owner permission.
    pub async fn get_permission(&self, evm_address: &str) -> Permission {
        let addr = Self::normalize_address(evm_address);

        if self.is_owner(&addr).await {
            return Permission::Owner;
        }

        if self.whitelist.read().await.contains(&addr) {
            return Permission::Whitelist;
        }

        Permission::Public
    }

    /// Whether `evm_address` is the claimed tapp owner (false while unclaimed).
    pub async fn is_owner(&self, evm_address: &str) -> bool {
        let addr = Self::normalize_address(evm_address);
        self.tapp_owner_address.read().await.as_deref() == Some(addr.as_str())
    }

    /// The claimed tapp owner address, if any.
    pub async fn owner_address(&self) -> Option<String> {
        self.tapp_owner_address.read().await.clone()
    }

    /// Claim tapp ownership for `evm_address` (first-come-first-served).
    /// Succeeds exactly once; returns the normalized owner address.
    /// Fails with the current owner if already claimed.
    pub async fn claim_owner(&self, evm_address: &str) -> Result<String, String> {
        let addr = Self::normalize_address(evm_address);
        let mut owner = self.tapp_owner_address.write().await;
        match &*owner {
            Some(current) => Err(current.clone()),
            None => {
                *owner = Some(addr.clone());
                Ok(addr)
            }
        }
    }

    /// Roll back a just-committed claim (only used when the measurement
    /// extension for the claim fails, before anything was persisted).
    pub async fn rollback_claim(&self) {
        *self.tapp_owner_address.write().await = None;
    }

    /// Persist the claimed owner to `owner_state_path` (no-op when unset).
    pub async fn persist_owner(&self) -> std::io::Result<()> {
        let Some(path) = &self.owner_state_path else {
            return Ok(());
        };
        let Some(owner) = self.owner_address().await else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, owner)
    }

    /// Read the owner persisted by a previous process of the current boot.
    pub fn load_persisted_owner(&self) -> Option<String> {
        let path = self.owner_state_path.as_ref()?;
        let content = std::fs::read_to_string(path).ok()?;
        let addr = content.trim();
        if addr.is_empty() {
            return None;
        }
        Some(Self::normalize_address(addr))
    }

    /// Set the owner directly (startup restore from config/persisted state).
    /// Unlike `claim_owner` this overwrites unconditionally — callers resolve
    /// config/persisted conflicts before calling.
    pub async fn set_owner(&self, evm_address: &str) -> String {
        let addr = Self::normalize_address(evm_address);
        *self.tapp_owner_address.write().await = Some(addr.clone());
        addr
    }

    /// Add address to whitelist (tapp owner only)
    pub async fn add_to_whitelist(&self, evm_address: String) -> Result<(), String> {
        let addr = Self::normalize_address(&evm_address);
        self.whitelist.write().await.insert(addr);
        Ok(())
    }

    /// Remove from whitelist (tapp owner only)
    pub async fn remove_from_whitelist(&self, evm_address: &str) -> Result<(), String> {
        let addr = Self::normalize_address(evm_address);
        self.whitelist.write().await.remove(&addr);
        Ok(())
    }

    /// List all whitelisted addresses
    pub async fn list_whitelist(&self) -> Vec<String> {
        self.whitelist.read().await.iter().cloned().collect()
    }

    /// Record app ownership when started
    pub async fn record_app_start(&self, app_id: String, owner_address: String) {
        let ownership = AppOwnership {
            app_id: app_id.clone(),
            owner_address: Self::normalize_address(&owner_address),
            started_at: chrono::Utc::now().timestamp(),
            status: AppStatus::Active,
            stopped_at: None,
        };
        self.app_ownership.write().await.insert(app_id, ownership);
    }

    /// Update app status to stopped
    pub async fn mark_app_stopped(&self, app_id: &str) {
        if let Some(ownership) = self.app_ownership.write().await.get_mut(app_id) {
            ownership.status = AppStatus::Stopped;
            ownership.stopped_at = Some(chrono::Utc::now().timestamp());
        }
    }

    /// Check if user can manage this app
    /// - Tapp owner can manage all apps
    /// - App owner can manage their own running apps
    pub async fn can_manage_app(&self, app_id: &str, evm_address: &str) -> bool {
        let addr = Self::normalize_address(evm_address);

        // Tapp owner can manage all apps
        if self.is_owner(&addr).await {
            return true;
        }

        // App owner can manage their own running apps
        if let Some(ownership) = self.app_ownership.read().await.get(app_id) {
            return ownership.owner_address == addr && ownership.status == AppStatus::Active;
        }

        false
    }

    /// Get app ownership info
    pub async fn get_app_ownership(&self, app_id: &str) -> Option<AppOwnership> {
        self.app_ownership.read().await.get(app_id).cloned()
    }

    /// List all app ownerships
    pub async fn list_all_ownerships(&self) -> Vec<AppOwnership> {
        self.app_ownership.read().await.values().cloned().collect()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_permission_levels() {
        let pm = PermissionManager::new(Some(
            "0x1234567890123456789012345678901234567890".to_string(),
        ));

        // Test tapp owner
        let perm = pm
            .get_permission("0x1234567890123456789012345678901234567890")
            .await;
        assert_eq!(perm, Permission::Owner);

        // Test public
        let perm = pm
            .get_permission("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
            .await;
        assert_eq!(perm, Permission::Public);

        // Add to whitelist
        pm.add_to_whitelist("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string())
            .await
            .unwrap();
        let perm = pm
            .get_permission("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
            .await;
        assert_eq!(perm, Permission::Whitelist);
    }

    #[tokio::test]
    async fn test_unclaimed_then_claim() {
        let pm = PermissionManager::new(None);
        let alice = "0xABCDEFabcdefABCDEFabcdefabcdefABCDEFabcd";
        let bob = "0x1234567890123456789012345678901234567890";

        // Unclaimed: nobody is owner
        assert!(pm.owner_address().await.is_none());
        assert_eq!(pm.get_permission(alice).await, Permission::Public);
        assert!(!pm.can_manage_app("any-app", alice).await);

        // First claim wins (address normalized)
        let owner = pm.claim_owner(alice).await.unwrap();
        assert_eq!(owner, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        assert_eq!(pm.get_permission(alice).await, Permission::Owner);

        // Second claim rejected, reports current owner
        let err = pm.claim_owner(bob).await.unwrap_err();
        assert_eq!(err, owner);
        assert_eq!(pm.get_permission(bob).await, Permission::Public);

        // Rollback reopens the claim (extend-measurement failure path)
        pm.rollback_claim().await;
        assert!(pm.owner_address().await.is_none());
        pm.claim_owner(bob).await.unwrap();
        assert_eq!(pm.get_permission(bob).await, Permission::Owner);
    }

    #[tokio::test]
    async fn test_owner_persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("tapp-owner-test-{}", std::process::id()));
        let state = dir.join("claimed_owner");
        let _ = std::fs::remove_dir_all(&dir);

        let pm = PermissionManager::new(None).with_owner_state_path(state.clone());
        assert!(pm.load_persisted_owner().is_none());

        pm.claim_owner("0xABCDEFabcdefABCDEFabcdefabcdefABCDEFabcd")
            .await
            .unwrap();
        pm.persist_owner().await.unwrap();

        // A fresh manager (process restart) restores the claim from disk
        let pm2 = PermissionManager::new(None).with_owner_state_path(state);
        let restored = pm2.load_persisted_owner().unwrap();
        assert_eq!(restored, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        pm2.set_owner(&restored).await;
        assert!(pm2.is_owner(&restored).await);
        // ... and the claim stays closed
        assert!(pm2.claim_owner("0x1234").await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_app_ownership_lifecycle() {
        let pm = PermissionManager::new(Some(
            "0x1234567890123456789012345678901234567890".to_string(),
        ));
        let app_owner = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";

        // Record ownership
        pm.record_app_start("test-app".to_string(), app_owner.to_string())
            .await;

        // App owner can manage running app
        assert!(pm.can_manage_app("test-app", app_owner).await);

        // Stop app
        pm.mark_app_stopped("test-app").await;

        // App owner can't manage stopped app
        assert!(!pm.can_manage_app("test-app", app_owner).await);

        // Tapp owner can still manage stopped apps
        assert!(
            pm.can_manage_app("test-app", "0x1234567890123456789012345678901234567890")
                .await
        );

        // Ownership record still exists
        let ownership = pm.get_app_ownership("test-app").await;
        assert!(ownership.is_some());
        assert_eq!(ownership.unwrap().status, AppStatus::Stopped);
    }

    #[test]
    fn test_address_normalization() {
        let addr1 =
            PermissionManager::normalize_address("1234567890123456789012345678901234567890");
        assert_eq!(addr1, "0x1234567890123456789012345678901234567890");

        let addr2 =
            PermissionManager::normalize_address("0x1234567890123456789012345678901234567890");
        assert_eq!(addr2, "0x1234567890123456789012345678901234567890");

        let addr3 =
            PermissionManager::normalize_address("0X1234567890123456789012345678901234567890");
        assert_eq!(addr3, "0x1234567890123456789012345678901234567890");
    }
}
