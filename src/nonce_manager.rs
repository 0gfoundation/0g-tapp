use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Nonce manager to prevent replay attacks
/// Tracks used nonces with expiration
pub struct NonceManager {
    // Map: nonce -> expiry timestamp
    used_nonces: Arc<RwLock<HashMap<String, i64>>>,
    // Nonce validity window in seconds (default: 5 minutes)
    validity_window: i64,
}

impl NonceManager {
    /// Create a new NonceManager with default validity window (300 seconds / 5 minutes)
    pub fn new() -> Self {
        Self::with_validity_window(300)
    }

    /// Create a new NonceManager with custom validity window
    pub fn with_validity_window(validity_window: i64) -> Self {
        let manager = Self {
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
            validity_window,
        };

        // Spawn background task to clean up expired nonces
        let nonces = manager.used_nonces.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                Self::cleanup_expired_nonces(&nonces).await;
            }
        });

        manager
    }

    /// Verify and consume a nonce
    /// Returns Ok(()) if nonce is valid and not used
    /// Returns Err if nonce is invalid, expired, or already used
    pub async fn verify_and_consume(
        &self,
        nonce: &str,
        timestamp: i64,
    ) -> Result<(), String> {
        let current_time = chrono::Utc::now().timestamp();

        // 1. Check timestamp validity
        let time_diff = (current_time - timestamp).abs();
        if time_diff > self.validity_window {
            return Err(format!(
                "Timestamp outside validity window. Diff: {}s, Max: {}s",
                time_diff, self.validity_window
            ));
        }

        // 2. Check if nonce already used
        let mut nonces = self.used_nonces.write().await;
        if nonces.contains_key(nonce) {
            return Err("Nonce already used (replay attack detected)".to_string());
        }

        // 3. Record nonce with expiry time
        let expiry = timestamp + self.validity_window;
        nonces.insert(nonce.to_string(), expiry);

        Ok(())
    }

    /// Clean up expired nonces
    async fn cleanup_expired_nonces(nonces: &Arc<RwLock<HashMap<String, i64>>>) {
        let current_time = chrono::Utc::now().timestamp();
        let mut nonces = nonces.write().await;

        let before_count = nonces.len();
        nonces.retain(|_, &mut expiry| expiry > current_time);
        let after_count = nonces.len();

        if before_count != after_count {
            tracing::debug!(
                removed = before_count - after_count,
                remaining = after_count,
                "Cleaned up expired nonces"
            );
        }
    }

    /// Get statistics about nonce usage
    pub async fn stats(&self) -> NonceStats {
        let nonces = self.used_nonces.read().await;
        NonceStats {
            active_nonces: nonces.len(),
            validity_window: self.validity_window,
        }
    }
}

#[derive(Debug)]
pub struct NonceStats {
    pub active_nonces: usize,
    pub validity_window: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_verify_and_consume() {
        let manager = NonceManager::with_validity_window(60);
        let nonce = "test-nonce-123";
        let timestamp = chrono::Utc::now().timestamp();

        // First use should succeed
        assert!(manager.verify_and_consume(nonce, timestamp).await.is_ok());

        // Second use should fail (replay)
        assert!(manager.verify_and_consume(nonce, timestamp).await.is_err());
    }

    #[tokio::test]
    async fn test_nonce_expired_timestamp() {
        let manager = NonceManager::with_validity_window(60);
        let nonce = "test-nonce-456";
        let old_timestamp = chrono::Utc::now().timestamp() - 120; // 2 minutes ago

        // Should fail due to expired timestamp
        assert!(manager.verify_and_consume(nonce, old_timestamp).await.is_err());
    }

    #[tokio::test]
    async fn test_nonce_future_timestamp() {
        let manager = NonceManager::with_validity_window(60);
        let nonce = "test-nonce-789";
        let future_timestamp = chrono::Utc::now().timestamp() + 120; // 2 minutes in future

        // Should fail due to future timestamp
        assert!(manager.verify_and_consume(nonce, future_timestamp).await.is_err());
    }
}
