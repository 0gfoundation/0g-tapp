# Version Management

## Overview

This workspace produces two binaries — **tapp-server** and **tapp-cli** — plus an internal library **tapp-common**. Alongside them lives the on-chain **TappRegistry** contract, which is also versioned. **Compatibility between artifacts is resolved at runtime rather than by matching version numbers** — see [Compatibility](#compatibility) below.

## Version Sources

| Crate | Version Location | Binary Output |
|---|---|---|
| tapp-server | Root `Cargo.toml` → `[package] version` | `tapp-server --version` |
| tapp-cli | `tapp-cli/Cargo.toml` → `[package] version` | `tapp-cli --version` |
| tapp-common | `tapp-common/Cargo.toml` → `[package] version` | (internal, no standalone release) |
| TappRegistry (contract) | Implementation version (on-chain `version()` view — see [Contract](#contract-tappregistry)) | `version()` call against the proxy |

## How to Build

```bash
# Build tapp-cli only (works on macOS, no TEE deps)
cargo build --release -p tapp-cli

# Build tapp-server only (requires Linux + TEE dependencies)
cargo build --release -p tapp-server

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
tapp-server-v<version>    # e.g. tapp-server-v0.1.0
tapp-cli-v<version>       # e.g. tapp-cli-v0.1.0
contract-v<version>       # e.g. contract-v0.1.0  (TappRegistry implementation)
```

Using the `v` prefix with crate name avoids ambiguity and sorts correctly in `git tag -l`.

## Versioning Policy

Each artifact uses `X.Y.Z`. What a digit means differs per artifact, because they
play different roles. All three artifacts baseline at **`0.1.0`**.

### tapp-server

| Digit | Bump when |
|---|---|
| **X** — MAJOR | Product-level major release / milestone. Not bumped automatically by code changes. |
| **Y** — MINOR | The **gRPC interface changed** — any change to the contract in `proto/tapp_service.proto` (new/removed/changed RPC, field, semantics, or validation). This is the server's *interface version*. |
| **Z** — PATCH | Everything else — bug fixes, internal refactors, new config options, non-wire behavior (e.g. adding a Unix-socket listener). |

### tapp-cli

The CLI is a **consumer**, so its version tracks its own user-facing surface,
**not** the wire interface:

| Digit | Bump when |
|---|---|
| **X** — MAJOR | Product-level major release / milestone. |
| **Y** — MINOR | Any user-facing CLI change — new command, new flag, changed output — **including purely client-side updates that touch no RPC**. |
| **Z** — PATCH | Bug fixes and internal changes. |

### contract (TappRegistry)

The contract's "interface" is its **ABI**:

| Digit | Bump when |
|---|---|
| **X** — MAJOR | Product-level major release / milestone. |
| **Y** — MINOR | The **ABI changed** — external/public function or event added, removed, or changed. |
| **Z** — PATCH | Logic-only change with an **unchanged ABI** — and it **must preserve storage layout** (beacon-upgrade safety, see below). |

Rules that apply to all three:

- `X` is reserved for product milestones; code changes never bump it on their own.
- Bump the relevant artifact's version in the **same PR** that makes the change.
- While in `0.x.y`, `X` stays `0`.

### Worked examples

- **Add Unix-socket support to the server** (new config + extra listener, gRPC
  contract unchanged) → **`tapp-server 0.1.0 → 0.1.1`** (PATCH). `tapp-cli`
  untouched.
- **Add a "node details" CLI command backed by a new server RPC** → the gRPC
  contract changed **and** the CLI gained a user-facing command →
  **`tapp-server → 0.2.0`** (interface) **and** **`tapp-cli → 0.2.0`** (feature).
- **Add a `--json` output flag to an existing CLI command** (no RPC touched) →
  **`tapp-cli` MINOR bump**, everything else unchanged. The gRPC interface does
  not move.

## Compatibility

Compatibility is **not** determined by comparing the three version numbers.
Instead, each interface has a version that lives on the **provider** side and is
read **at runtime** by the consumer:

| Edge | Interface | Version source (read at runtime) |
|---|---|---|
| `tapp-cli` ↔ `tapp-server` | gRPC contract | Server version, returned by `GetTappInfo` |
| `tapp-server` / `tapp-cli` ↔ contract | on-chain ABI | Implementation version, returned by the contract's `version()` view |

### Report the full version; compare only `MAJOR.MINOR`

- The provider always **reports the complete `X.Y.Z`** — `GetTappInfo` and the
  contract's `version()` return the full version, nothing is dropped.
- The **compatibility check compares only `MAJOR.MINOR`** (the first two digits),
  because **PATCH never changes the interface** — `0.2.1` and `0.2.7` speak the
  exact same gRPC contract / ABI, so the patch digit is irrelevant when deciding
  compatibility.

### Runtime check — warn, never hard-block

When a consumer connects (CLI → server) or before an on-chain call
(CLI/server → contract), it reads the provider's reported version, takes its
`MAJOR.MINOR`, and compares against the interface version it was built for:

- **MAJOR differs** → strong warning: interfaces are on different major lines,
  likely incompatible.
- **Same MAJOR, provider MINOR is older than the consumer needs** → soft
  warning: "peer interface is older; newer commands may fail."
- **Otherwise** → proceed silently.

The consumer never refuses the connection. If a command genuinely relies on an
RPC/function the peer lacks, that single call fails with a clear error (gRPC
unimplemented, or an on-chain revert) — so the ground truth is enforced at the
call, and the version check is only an early, friendly heads-up.

Rationale: `tapp-cli` is installed independently (e.g. `/usr/local/bin/tapp-cli`)
across many machines while servers on individual TEE nodes upgrade on their own
schedule, so version skew is normal. A hard block would strand an old CLI that
only uses unchanged commands.

### How the consumer knows the interface version it needs

`tapp-cli` and `tapp-server` are built from the same repo, so at **build time**
we stamp the current provider interface version into the consumer (the server's
`MAJOR.MINOR` for the gRPC edge). This requires **no manual maintenance**. It is
slightly conservative — a CLI may warn against an older server that in fact has
every RPC the CLI actually calls — but since the check only warns and the real
failure surfaces at the call, this is harmless.

*(Alternative, if precision is ever needed: maintain an explicit
`REQUIRES_SERVER_API` / `REQUIRES_CONTRACT` constant, bumped only when the
consumer starts depending on a newer interface feature.)*

## Contract (TappRegistry)

The contract is deployed behind a **BeaconProxy + UpgradeableBeacon (ERC-1967)**
pattern (`contract/src/proxy/`), so it is **upgradeable in place**:

- The **proxy address is stable** — this is the `contract_address` that
  `tapp-server` / `tapp-cli` are configured with. It does **not** change across
  versions.
- An upgrade deploys a **new implementation** and points the beacon at it
  (`contract/script/Upgrade.s.sol`: `beacon.upgradeTo(newImpl)`).

Consequences for versioning:

- Because the address is stable while the implementation behind it can change,
  **you cannot infer the contract version from the address** — runtime
  introspection is required. Add a **`version()` view** to the implementation
  returning its full `X.Y.Z`, bumped per the rules above on every upgrade. This
  is the on-chain analogue of the server's `GetTappInfo`.
- **Preserve storage layout** across implementations — mandatory for beacon
  upgrades. Layout-affecting changes are not PATCH-safe.
- **Prefer additive ABI changes** so binaries built against an older ABI keep
  working. A breaking ABI upgrade lands on **every** binary pointing at the
  beacon at once, so it must be **coordinated** with a `tapp-server` / `tapp-cli`
  rollout.
- Track in `contract/CONTRACTS.md`: the stable **proxy and beacon addresses**
  plus the **implementation version history** (which version is live now, and
  what each upgrade changed).
