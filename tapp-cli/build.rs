//! Stamp the gRPC interface version this CLI is built against into the binary.
//!
//! The gRPC interface version is the tapp-server `MAJOR.MINOR` (see
//! `docs/VERSIONING.md`). tapp-cli and tapp-server live in the same workspace,
//! so we read the server's version straight from the workspace root
//! `Cargo.toml` at build time — no separate number to maintain. It is exposed
//! as the `TAPP_EXPECTED_SERVER_VERSION` compile-time env var.

use std::path::Path;

fn main() {
    let root_manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    println!("cargo:rerun-if-changed={}", root_manifest.display());

    let text = std::fs::read_to_string(&root_manifest)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", root_manifest.display()));

    let version = package_version(&text).unwrap_or_else(|| {
        panic!(
            "could not find [package] version in {}",
            root_manifest.display()
        )
    });

    println!("cargo:rustc-env=TAPP_EXPECTED_SERVER_VERSION={version}");
}

/// Extract the `version` value from the `[package]` table of a Cargo manifest,
/// ignoring the `[workspace.package]` table that precedes it.
fn package_version(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = line.strip_prefix("version") {
                let value = rest.trim_start().strip_prefix('=')?.trim();
                return Some(value.trim_matches('"').to_string());
            }
        }
    }
    None
}
