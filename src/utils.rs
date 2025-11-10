use sha2::{Digest, Sha256, Sha384};

/// Calculate SHA-256 hash of data
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Calculate SHA-256 hash and return as hex string
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Calculate SHA-384 hash of data
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Calculate SHA-384 hash and return as hex string
pub fn sha384_hex(data: &[u8]) -> String {
    hex::encode(sha384(data))
}

/// Pad data to specified length with zeros
pub fn pad_to_length(data: &[u8], length: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.resize(length, 0);
    padded
}

/// Validate application ID format
pub fn validate_app_id(app_id: &str) -> bool {
    // App ID should be alphanumeric with hyphens and underscores
    // Length between 0 and 64 characters
    if app_id.is_empty() || app_id.len() > 64 {
        return false;
    }

    app_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Generate a unique session ID
pub fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Current timestamp in seconds since Unix epoch
pub fn current_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Format bytes as human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}
