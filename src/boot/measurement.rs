use crate::error::{DockerError, TappResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};
use serde_yaml::Value;

/// Hash algorithm for measurement calculation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    /// Calculate hash using the specified algorithm and return as hex string
    pub fn hash(&self, data: &[u8]) -> String {
        match self {
            HashAlgorithm::Sha256 => crate::utils::sha256_hex(data),
            HashAlgorithm::Sha384 => crate::utils::sha384_hex(data),
        }
    }
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::Sha384
    }
}

/// Application measurement data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMeasurement {
    pub app_id: String,
    pub compose_hash: String,
    pub volumes_hash: String,
    pub deployer: String,
    pub timestamp: i64,
}

/// Docker Compose measurement calculator
pub struct ComposeMeasurement {
    hash_algorithm: HashAlgorithm,
}

impl ComposeMeasurement {
    pub fn new() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::default(),
        }
    }

    pub fn with_hash_algorithm(hash_algorithm: HashAlgorithm) -> Self {
        Self { hash_algorithm }
    }

    /// Calculate hash of Docker Compose file content
    pub fn calculate_compose_hash(&self, compose_content: &str) -> TappResult<String> {
        // Normalize the compose content to ensure consistent hashing
        let normalized = self.normalize_compose_content(compose_content)?;
        Ok(self.hash_algorithm.hash(normalized.as_bytes()))
    }

    pub fn calculate_mount_files_hash(
        &self,
        mount_files: &[crate::boot::manager::MountFile],
    ) -> TappResult<(String, String)> {
        if mount_files.is_empty() {
            return Ok((self.hash_algorithm.hash(b""), "".to_string()));
        }

        // Sort files by source path for deterministic ordering
        let mut sorted_files: Vec<_> = mount_files.iter().collect();
        sorted_files.sort_by(|a, b| a.source_path.cmp(&b.source_path));

        // Calculate leaf hashes (hash of each file content)
        let leaf_hashes: Vec<String> = sorted_files
            .iter()
            .map(|file| self.hash_algorithm.hash(&file.content))
            .collect();

        // Build Merkle tree to get root hash
        let root_hash = self.build_merkle_root(&leaf_hashes)?;

        // Combine file contents with filename headers
        const FILE_SEPARATOR: &str = "\x1E"; // Record Separator
        let combined_content: String = sorted_files
            .iter()
            .map(|file| {
                format!(
                    "--- FILE: {} ---\n{}",
                    file.source_path,
                    String::from_utf8_lossy(&file.content)
                )
            })
            .collect::<Vec<_>>()
            .join(FILE_SEPARATOR);

        Ok((root_hash, combined_content))
    }

    /// Build Merkle tree root hash from leaf hashes
    fn build_merkle_root(&self, leaf_hashes: &[String]) -> TappResult<String> {
        if leaf_hashes.is_empty() {
            return Ok(self.hash_algorithm.hash(b""));
        }

        if leaf_hashes.len() == 1 {
            return Ok(leaf_hashes[0].clone());
        }

        let mut current_level = leaf_hashes.to_vec();

        // Build tree bottom-up until we get the root
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            // Process pairs of hashes
            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    // Combine two hashes
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    // Odd number: duplicate the last hash (standard Merkle tree approach)
                    format!("{}{}", chunk[0], chunk[0])
                };

                let parent_hash = self.hash_algorithm.hash(combined.as_bytes());
                next_level.push(parent_hash);
            }

            current_level = next_level;
        }

        Ok(current_level[0].clone())
    }

    /// Normalize Docker Compose content for consistent hashing
    fn normalize_compose_content(&self, content: &str) -> TappResult<String> {
        // Parse and re-serialize to normalize formatting
        let parsed: Value =
            serde_yaml::from_str(content).map_err(|e| DockerError::InvalidComposeContent {
                reason: format!("YAML parse error: {}", e),
            })?;

        // Convert to JSON for consistent serialization
        let json_str =
            serde_json::to_string(&parsed).map_err(|e| DockerError::InvalidComposeContent {
                reason: format!("JSON serialization error: {}", e),
            })?;

        self.normalize_json_content(&json_str)
    }

    fn normalize_json_content(&self, json_str: &str) -> TappResult<String> {
        let parsed: JsonValue =
            serde_json::from_str(json_str).map_err(|e| DockerError::InvalidComposeContent {
                reason: format!("JSON parse error: {}", e),
            })?;

        let sorted = Self::sort_json_keys(&parsed);

        Ok(serde_json::to_string_pretty(&sorted).map_err(|e| {
            DockerError::InvalidComposeContent {
                reason: format!("JSON serialization error: {}", e),
            }
        })?)
    }

    fn sort_json_keys(value: &JsonValue) -> JsonValue {
        match value {
            JsonValue::Object(map) => {
                let mut sorted = Map::new();
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();

                for key in keys {
                    sorted.insert(key.clone(), Self::sort_json_keys(&map[key]));
                }
                JsonValue::Object(sorted)
            }
            JsonValue::Array(arr) => {
                JsonValue::Array(arr.iter().map(Self::sort_json_keys).collect())
            }
            _ => value.clone(),
        }
    }
}

impl Default for ComposeMeasurement {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_compose_hash() {
        let measurement = ComposeMeasurement::new();

        let compose1 = r#"
version: '3.8'
services:
  web:
    image: nginx
"#;

        let compose2 = r#"
version: "3.8"
services:
  web:
    image: "nginx"
"#;

        let hash1 = measurement.calculate_compose_hash(compose1).unwrap();
        let hash2 = measurement.calculate_compose_hash(compose2).unwrap();

        // Should be the same despite formatting differences
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_normalize_json_content() {
        let measurement = ComposeMeasurement::new();

        let json1 = r#"{"b": 2, "a": 1}"#;
        let json2 = r#"{"a": 1, "b": 2}"#;

        let norm1 = measurement.normalize_json_content(json1).unwrap();
        let norm2 = measurement.normalize_json_content(json2).unwrap();

        // Should be the same despite key ordering
        assert_eq!(norm1, norm2);
    }
}
