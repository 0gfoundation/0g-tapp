//! Compose-file checks for data placement and container privilege.
//!
//! The encrypted per-app volume only protects what lands under `./data`, so a
//! compose file can silently opt out of it — a named volume writes to docker's
//! shared data-root, an absolute bind mount writes anywhere on the host. Neither
//! is caught by anything else: docker accepts both happily. This lint makes the
//! escape visible.
//!
//! Warning-only for now: existing apps (and nearly every database example on the
//! internet) use named volumes, so rejection starts as a migration signal, not a
//! gate. Tightening to refusal is a one-line change at the call site once the
//! fleet has moved.

/// Human-readable violations found in a compose file. Empty means clean.
/// Unparseable YAML yields no findings — compose itself will reject it with a
/// better message than this lint could.
pub fn lint_compose(compose_content: &str) -> Vec<String> {
    let doc: serde_yaml::Value = match serde_yaml::from_str(compose_content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut findings = Vec::new();

    let services = match doc.get("services").and_then(|s| s.as_mapping()) {
        Some(m) => m,
        None => return findings,
    };

    for (name, service) in services {
        let service_name = name.as_str().unwrap_or("?");

        if service
            .get("privileged")
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            findings.push(format!(
                "service '{service_name}': privileged=true grants full host access, \
                 bypassing every isolation and encryption boundary"
            ));
        }

        let volumes = match service.get("volumes").and_then(|v| v.as_sequence()) {
            Some(seq) => seq,
            None => continue,
        };
        for vol in volumes {
            if let Some(finding) = check_volume(service_name, vol) {
                findings.push(finding);
            }
        }
    }
    findings
}

/// One volume entry, in either compose syntax. Returns a finding or None.
fn check_volume(service: &str, vol: &serde_yaml::Value) -> Option<String> {
    // Long syntax: {type: bind|volume|tmpfs, source: ..., target: ...}
    if let Some(map) = vol.as_mapping() {
        let vol_type = map
            .get(serde_yaml::Value::from("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("volume");
        return match vol_type {
            "tmpfs" => None, // RAM only, nothing persists
            "volume" => Some(format!(
                "service '{service}': named volume stores data in docker's shared \
                 data-root, OUTSIDE the app's encrypted volume — use a './data/...' \
                 bind mount instead"
            )),
            "bind" => {
                let source = map
                    .get(serde_yaml::Value::from("source"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                check_bind_source(service, source)
            }
            _ => None,
        };
    }

    // Short syntax: "source:target[:mode]" or a bare target (anonymous volume)
    let entry = vol.as_str()?;
    let source = match entry.split(':').next() {
        Some(s) if entry.contains(':') => s,
        _ => {
            return Some(format!(
                "service '{service}': anonymous volume '{entry}' stores data in \
                 docker's shared data-root, outside the app's encrypted volume"
            ))
        }
    };
    if source.starts_with('.') || source.starts_with('/') || source.starts_with('~') {
        check_bind_source(service, source)
    } else if source.contains("${") {
        Some(format!(
            "service '{service}': volume source '{source}' uses a variable — \
             cannot verify it stays inside the app directory"
        ))
    } else {
        Some(format!(
            "service '{service}': named volume '{source}' stores data in docker's \
             shared data-root, OUTSIDE the app's encrypted volume — use a \
             './data/...' bind mount instead"
        ))
    }
}

fn check_bind_source(service: &str, source: &str) -> Option<String> {
    if source.contains("docker.sock") {
        return Some(format!(
            "service '{service}': mounting the docker socket hands the app control \
             of every container on this machine"
        ));
    }
    if source.starts_with('/') || source.starts_with('~') {
        return Some(format!(
            "service '{service}': absolute bind mount '{source}' writes outside the \
             app's encrypted volume — keep app data under './data/...'"
        ));
    }
    // Relative: fine as long as it cannot climb out of the app directory.
    // (Writes to relative paths outside ./data land on the RAM overlay — not
    // encrypted, but never persisted to disk either, so they are not flagged.)
    if source.split('/').any(|seg| seg == "..") {
        return Some(format!(
            "service '{service}': volume source '{source}' escapes the app directory"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lint(yaml: &str) -> Vec<String> {
        lint_compose(yaml)
    }

    #[test]
    fn data_bind_mounts_are_clean() {
        let findings = lint(
            "services:\n  db:\n    image: postgres\n    volumes:\n      - ./data/pg:/var/lib/postgresql/data:rw\n      - ./config.json:/etc/app/config.json\n",
        );
        assert!(findings.is_empty(), "unexpected: {findings:?}");
    }

    #[test]
    fn named_volume_is_flagged_in_both_syntaxes() {
        let short = lint("services:\n  db:\n    volumes:\n      - pgdata:/var/lib/postgresql/data\n");
        assert_eq!(short.len(), 1);
        assert!(short[0].contains("named volume"));

        let long = lint(
            "services:\n  db:\n    volumes:\n      - type: volume\n        source: pgdata\n        target: /var/lib/postgresql/data\n",
        );
        assert_eq!(long.len(), 1, "long syntax must be caught too: {long:?}");
    }

    #[test]
    fn escapes_are_flagged_absolute_socket_traversal_anonymous() {
        let yaml = "services:\n  app:\n    volumes:\n      - /etc/passwd:/host/passwd\n      - /var/run/docker.sock:/var/run/docker.sock\n      - ../other-app/data:/steal\n      - /cache\n";
        let findings = lint(yaml);
        assert_eq!(findings.len(), 4, "{findings:?}");
        assert!(findings.iter().any(|f| f.contains("docker socket")));
        assert!(findings.iter().any(|f| f.contains("escapes")));
        assert!(findings.iter().any(|f| f.contains("anonymous")));
    }

    #[test]
    fn privileged_and_tmpfs_and_variables() {
        let yaml = "services:\n  app:\n    privileged: true\n    volumes:\n      - type: tmpfs\n        target: /scratch\n      - ${DATA_DIR}:/data\n";
        let findings = lint(yaml);
        assert_eq!(findings.len(), 2, "{findings:?}"); // privileged + variable; tmpfs clean
        assert!(findings.iter().any(|f| f.contains("privileged")));
        assert!(findings.iter().any(|f| f.contains("variable")));
    }

    #[test]
    fn garbage_yaml_and_no_volumes_yield_nothing() {
        assert!(lint(": not yaml ::").is_empty());
        assert!(lint("services:\n  app:\n    image: nginx\n").is_empty());
    }
}
