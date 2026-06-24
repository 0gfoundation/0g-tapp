# Version Management

## Overview

This workspace produces two independent binaries — **tapp-server** and **tapp-cli** — plus an internal library **tapp-common**. Each has its own version number.

## Version Sources

| Crate | Version Location | Binary Output |
|---|---|---|
| tapp-server | Root `Cargo.toml` → `[package] version` | `tapp-server --version` |
| tapp-cli | `tapp-cli/Cargo.toml` → `[package] version` | `tapp-cli --version` |
| tapp-common | `tapp-common/Cargo.toml` → `[package] version` | (internal, no standalone release) |

## How to Build

```bash
# Build tapp-cli only (works on macOS, no TEE deps)
cargo build --release -p tapp-cli

# Build tapp-server only (requires Linux + TEE dependencies)
cargo build --release -p tapp-service

# Build everything
cargo build --release
```

Note: in a workspace with multiple binaries, you must use `-p <package>`
to select which one to build/run. `cargo build --bin tapp-cli` without
`-p` only searches the default-run package.

## How to Check Version at Runtime

```bash
# CLI
tapp-cli --version      # or: tapp-cli -V

# Server
tapp-server --version   # or: tapp-server -V
# Server startup log also prints: "🚀 Starting TDX TAPP Service Server v0.1.0"
```

Version is injected at compile time via `env!("CARGO_PKG_VERSION")` — no hardcoded strings.

## Bump Workflow

### tapp-cli release

1. Edit `tapp-cli/Cargo.toml`:
   ```toml
   version = "0.2.0"   # was "0.1.0"
   ```
2. Commit with message: `chore(tapp-cli): bump version to 0.2.0`
3. Tag: `git tag tapp-cli-v0.2.0`
4. Push: `git push origin tapp-cli-v0.2.0`
5. CI auto-builds and creates GitHub Release.

### tapp-server release

1. Edit root `Cargo.toml`:
   ```toml
   version = "0.2.0"   # was "0.1.0"
   ```
2. Commit with message: `chore(tapp-server): bump version to 0.2.0`
3. Tag: `git tag tapp-server-v0.2.0`
4. Push: `git push origin tapp-server-v0.2.0`
5. CI auto-builds and creates GitHub Release.

### tapp-common (rare)

tapp-common is an internal dependency, not a standalone release artifact. Bump its version only on breaking API changes that affect downstream crates. Both tapp-cli and tapp-server pin it via path dependency, so a tapp-common bump requires rebuilding dependents.

## Tag Naming Convention

```
tapp-server-v<version>    # e.g. tapp-server-v0.1.1
tapp-cli-v<version>       # e.g. tapp-cli-v0.1.1
```

Using the `v` prefix with crate name avoids ambiguity and sorts correctly in `git tag -l`.

## Versioning Policy

- Follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`
  - **MAJOR**: incompatible API changes
  - **MINOR**: new features, backward-compatible
  - **PATCH**: bug fixes, backward-compatible
- Currently in `0.x.y` — anything may change between minor versions.
- When a PR introduces user-visible changes (new command, changed flag, behavior), bump the relevant crate's version in the same PR.
