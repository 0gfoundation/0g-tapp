//! CLI ↔ server interface-version compatibility check.
//!
//! Compatibility is decided on the `MAJOR.MINOR` of the peer's reported version
//! — `PATCH` never changes the interface, so it is ignored here. See
//! `docs/VERSIONING.md` for the full policy.

/// Parse the `MAJOR.MINOR` interface identity from a full `X.Y.Z` version
/// string, ignoring the `PATCH` digit. Returns `None` if the string does not
/// look like a version.
fn major_minor(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.trim().trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Compare a peer's reported full version against the interface version this
/// build was compiled for. Returns a human-readable warning when they may be
/// incompatible, or `None` when compatible.
///
/// Only `MAJOR.MINOR` is considered:
/// - different `MAJOR` → likely incompatible (different interface major line);
/// - same `MAJOR`, peer `MINOR` older than expected → newer commands may fail;
/// - otherwise → compatible (peer is same or newer, additive changes are safe).
///
/// If either version cannot be parsed, returns `None` (no spurious warning).
pub fn interface_warning(peer_version: &str, expected_version: &str) -> Option<String> {
    let (peer_major, peer_minor) = major_minor(peer_version)?;
    let (exp_major, exp_minor) = major_minor(expected_version)?;

    if peer_major != exp_major {
        Some(format!(
            "server interface v{peer_major}.{peer_minor} is on a different major line than this CLI expects (v{exp_major}.{exp_minor}); they are likely incompatible"
        ))
    } else if peer_minor < exp_minor {
        Some(format!(
            "server interface v{peer_major}.{peer_minor} is older than this CLI expects (v{exp_major}.{exp_minor}); newer commands may fail"
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::interface_warning;

    #[test]
    fn patch_is_ignored() {
        assert!(interface_warning("0.2.7", "0.2.1").is_none());
        assert!(interface_warning("0.2.0", "0.2.9").is_none());
    }

    #[test]
    fn newer_server_is_ok() {
        assert!(interface_warning("0.3.0", "0.2.0").is_none());
    }

    #[test]
    fn older_server_minor_warns() {
        assert!(interface_warning("0.1.0", "0.2.0").is_some());
    }

    #[test]
    fn major_mismatch_warns() {
        assert!(interface_warning("1.0.0", "0.2.0").is_some());
        assert!(interface_warning("0.9.9", "1.0.0").is_some());
    }

    #[test]
    fn unparseable_is_silent() {
        assert!(interface_warning("", "0.1.0").is_none());
        assert!(interface_warning("dev", "0.1.0").is_none());
    }
}
