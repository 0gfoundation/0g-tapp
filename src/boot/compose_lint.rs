//! Compose-file checks for data placement and container privilege.
//!
//! The encrypted per-app volume protects what lands under `./data` — which,
//! since compose_override.rs redirects them, includes plainly-declared named
//! volumes. What this lint flags is everything that still escapes: bind mounts
//! outside the app directory, volumes the user configured to live elsewhere
//! (`external`, a driver), anonymous volumes, plus the two privilege escapes
//! (docker.sock, privileged) that hand the app the whole machine.
//!
//! Warning-only for now: rejection starts as a migration signal, not a gate.
//! Tightening to refusal is a one-line change at the call site.

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
    let redirected = super::compose_override::redirectable_volumes(compose_content);

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
            if let Some(finding) = check_volume(service_name, vol, &redirected) {
                findings.push(finding);
            }
        }
    }
    findings
}

/// Writable bind mounts that reach tapp-server's own state: the claimed owner, the
/// claimed config and the scratch key all live in `state_dir` (tmpfs, `/run/tapp`), and
/// are read back on a process restart without being measured again. A container that
/// can write there can swap the owner or the trust anchor in force. Not a warning like
/// the rest of this module: these are refused.
///
/// Refused: a writable mount of the directory itself or anything above it (`/run`, `/`,
/// also through a symlink such as `/var/run`), or of a path inside it other than the
/// socket, which apps are meant to mount. Read-only mounts are fine.
pub fn state_dir_exposures(
    compose_content: &str,
    state_dir: &std::path::Path,
    socket: Option<&std::path::Path>,
) -> Vec<String> {
    let doc: serde_yaml::Value = match serde_yaml::from_str(compose_content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(services) = doc.get("services").and_then(|s| s.as_mapping()) else {
        return Vec::new();
    };
    let state_dir = resolve(state_dir);
    let socket = socket.map(resolve);
    let mut findings = Vec::new();
    for (name, service) in services {
        let service_name = name.as_str().unwrap_or("?");
        let Some(volumes) = service.get("volumes").and_then(|v| v.as_sequence()) else {
            continue;
        };
        for vol in volumes {
            let Some((source, read_only)) = bind_source(vol) else { continue };
            if read_only || !source.starts_with('/') {
                continue;
            }
            let source = resolve(std::path::Path::new(source));
            let covers = state_dir.starts_with(&source);
            let inside = source.starts_with(&state_dir) && Some(&source) != socket.as_ref();
            if covers || inside {
                findings.push(format!(
                    "service '{service_name}': writable mount of '{}' reaches tapp-server's \
                     own state in {} (claimed owner, trust anchors) — mount only the socket, \
                     or mount read-only",
                    source.display(),
                    state_dir.display()
                ));
            }
        }
    }
    findings
}

/// The host path a bind mount names and whether it is read-only, in either syntax.
fn bind_source(vol: &serde_yaml::Value) -> Option<(&str, bool)> {
    if let Some(map) = vol.as_mapping() {
        if map.get(serde_yaml::Value::from("type")).and_then(|t| t.as_str()) != Some("bind") {
            return None;
        }
        let source = map.get(serde_yaml::Value::from("source"))?.as_str()?;
        let ro = map
            .get(serde_yaml::Value::from("read_only"))
            .and_then(|r| r.as_bool())
            .unwrap_or(false);
        return Some((source, ro));
    }
    let mut parts = vol.as_str()?.split(':');
    let source = parts.next()?;
    parts.next()?; // a bare target is an anonymous volume, not a bind
    let ro = parts
        .next()
        .map(|opts| opts.split(',').any(|o| o == "ro"))
        .unwrap_or(false);
    Some((source, ro))
}

/// Symlinks resolved where the path exists (`/var/run` is `/run`), so a mount cannot reach
/// the state directory by another name; trailing slashes and `.` dropped otherwise.
fn resolve(p: &std::path::Path) -> std::path::PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.components().collect())
}

/// One volume entry, in either compose syntax. Returns a finding or None.
/// `redirected` is the set of named volumes compose_override.rs sends into the
/// encrypted volume — using one of those is the blessed path, not a finding.
fn check_volume(service: &str, vol: &serde_yaml::Value, redirected: &[String]) -> Option<String> {
    // Long syntax: {type: bind|volume|tmpfs, source: ..., target: ...}
    if let Some(map) = vol.as_mapping() {
        let vol_type = map
            .get(serde_yaml::Value::from("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("volume");
        return match vol_type {
            "tmpfs" => None, // RAM only, nothing persists
            "volume" => {
                let source = map
                    .get(serde_yaml::Value::from("source"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                named_volume_finding(service, source, redirected)
            }
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
        named_volume_finding(service, source, redirected)
    }
}

/// A named volume is fine exactly when the override redirects it. One that is
/// not redirected was either configured by the user to live elsewhere
/// (external, a driver — a deliberate escape worth pointing at) or never
/// declared (compose itself will refuse it, but say why here too).
fn named_volume_finding(service: &str, source: &str, redirected: &[String]) -> Option<String> {
    if redirected.iter().any(|r| r == source) {
        return None;
    }
    Some(format!(
        "service '{service}': named volume '{source}' is configured to live outside \
         the app's encrypted volume (external / custom driver / undeclared) — its \
         data is NOT encrypted at rest"
    ))
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
mod state_dir_tests {
    use super::*;
    use std::path::Path;

    fn check(volume: &str) -> Vec<String> {
        let compose = format!("services:\n  app:\n    image: x\n    volumes:\n      - {volume}\n");
        state_dir_exposures(&compose, Path::new("/run/tapp"), Some(Path::new("/run/tapp/tapp.sock")))
    }

    #[test]
    fn the_socket_and_read_only_mounts_are_fine() {
        assert!(check("/run/tapp/tapp.sock:/run/tapp/tapp.sock").is_empty());
        assert!(check("/run/tapp:/run/tapp:ro").is_empty());
        assert!(check("./data:/data").is_empty());
        assert!(check("/data/kms:/var/lib/kms").is_empty());
    }

    #[test]
    fn a_writable_mount_reaching_the_state_is_refused() {
        for v in ["/run/tapp:/run/tapp", "/run/tapp/:/x", "/run:/host-run", "/:/host", "/run/tapp/claimed_owner:/o", "/run/tapp:/x:rw"] {
            assert_eq!(check(v).len(), 1, "{v}");
        }
    }

    #[test]
    fn long_syntax_is_checked_too() {
        let c = "services:\n  app:\n    image: x\n    volumes:\n      - type: bind\n        source: /run\n        target: /r\n";
        assert_eq!(state_dir_exposures(c, Path::new("/run/tapp"), None).len(), 1);
        let ro = "services:\n  app:\n    image: x\n    volumes:\n      - type: bind\n        source: /run\n        target: /r\n        read_only: true\n";
        assert!(state_dir_exposures(ro, Path::new("/run/tapp"), None).is_empty());
    }
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
    fn a_declared_named_volume_is_clean_because_the_override_redirects_it() {
        let short = lint(
            "services:\n  db:\n    volumes:\n      - pgdata:/var/lib/postgresql/data\nvolumes:\n  pgdata:\n",
        );
        assert!(short.is_empty(), "redirected volume must not be flagged: {short:?}");

        let long = lint(
            "services:\n  db:\n    volumes:\n      - type: volume\n        source: pgdata\n        target: /var/lib/postgresql/data\nvolumes:\n  pgdata:\n",
        );
        assert!(long.is_empty(), "long syntax too: {long:?}");
    }

    #[test]
    fn an_unredirectable_named_volume_is_flagged() {
        // external: true is a user choice to live outside — visible, not rewritten.
        let external = lint(
            "services:\n  db:\n    volumes:\n      - pgdata:/var/lib/postgresql/data\nvolumes:\n  pgdata:\n    external: true\n",
        );
        assert_eq!(external.len(), 1);
        assert!(external[0].contains("NOT encrypted"));

        // Undeclared: compose refuses it anyway, but the reason shows here too.
        let undeclared =
            lint("services:\n  db:\n    volumes:\n      - pgdata:/var/lib/postgresql/data\n");
        assert_eq!(undeclared.len(), 1, "{undeclared:?}");
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
