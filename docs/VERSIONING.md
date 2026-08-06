# Version Management

## Overview

This workspace produces two binaries — **tapp-server** and **tapp-cli** — plus an internal library **tapp-common**. Alongside them live the on-chain **TappRegistry** contract and the **CVM image** (the confidential VM the server runs inside), both also versioned. **Compatibility between artifacts is resolved at runtime rather than by matching version numbers** — see [Compatibility](#compatibility) below.

## Version Sources

| Crate | Version Location | Binary Output |
|---|---|---|
| tapp-server | Root `Cargo.toml` → `[package] version` | `tapp-server --version` |
| tapp-cli | `tapp-cli/Cargo.toml` → `[package] version` | `tapp-cli --version` |
| tapp-common | `tapp-common/Cargo.toml` → `[package] version` | (internal, no standalone release) |
| TappRegistry (contract) | Implementation version (on-chain `version()` view — see [Contract](#contract-tappregistry)) | `version()` call against the proxy |
| CVM image | `build-cvm` workflow inputs `version` + `image_rev` — see [CVM image](#cvm-image) | published image name, e.g. `og-tdx-dev-grub-v0-3-0-r2` |

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

### Binary release (tapp-server and tapp-cli)

**A tag names a release, not a binary version.** One tag produces one GitHub Release
containing *both* binaries, each reporting whatever its own `Cargo.toml` says. The two
things are independent, and that is what lets the binaries move at different speeds without
needing separate tags.

```bash
# 1. Edit whichever Cargo.toml actually changed — one, both, or neither.
#      tapp-server → root Cargo.toml
#      tapp-cli    → tapp-cli/Cargo.toml
# 2. Commit, e.g.  chore(tapp-cli): bump version to 0.4.1
# 3. Tag the release. Conventionally the version of whatever moved:
git tag v0.4.1
git push origin v0.4.1
# 4. build.yml fires on v* and publishes the release: both binaries, both cosign
#    bundles, and one SHA256SUMS covering both.
```

So a release where only the CLI moved looks like: tag `v0.4.1`, and inside it
`tapp-cli --version` → `0.4.1` while `tapp-server --version` → `0.4.0`. That is correct and
expected — do not bump a binary that did not change just to make the numbers line up. To
find out what you actually have, ask the binary, never the tag it came from.

A change can also ride an existing version instead of earning a new one, and **whether it
reaches users depends entirely on whether the tag has been cut yet**:

- **Before tagging — it ships.** The `measure_only` fix landed in `f45299c` with tapp-server
  deliberately held at 0.3.0, and `v0.3.0` was tagged afterwards, so the released binary
  contains it.
- **After tagging — it does not.** The `--as-endpoint` default was corrected in `bce9954`,
  after `v0.4.0` had been tagged and released. Version numbers stayed put, so the published
  `tapp-cli` still has the old default and always will; the fix only reaches users at the
  next release.

Moving a tag to close that gap is not an option: release artifacts are cosign-signed, so
re-cutting them under the same version means two different binaries with two different
signatures for one version — the exact thing signing exists to prevent. Either bump and cut
a new tag, or accept that the released binary keeps the old behaviour until the next one.

Only the binaries share a release. The contract and the CVM image are versioned and shipped
separately — see below.

### tapp-common (rare)

tapp-common is an internal dependency, not a standalone release artifact. Bump its version only on breaking API changes that affect downstream crates. Both tapp-cli and tapp-server pin it via path dependency, so a tapp-common bump requires rebuilding dependents.

### CVM image release

The image is **not** built from a git tag — it is built by dispatching the `build-cvm` workflow. Its version is `<tapp-server version>[-r<image_rev>]`:

1. Dispatch `build-cvm` with `version` = the **tapp-server** version (`tapp-server --version`, i.e. root `Cargo.toml`) and `image_rev` = the image revision (see [CVM image](#cvm-image) for when to bump it). Take it from the binary, not from the release tag it shipped under — a release named `v0.4.1` can perfectly well contain tapp-server 0.4.0, and the image version has to follow the server.
2. The workflow publishes the image, writes the reference values and registers the AS policy — all three keyed on the image version, not the binary version.
3. Tag the commit the image was built from, for traceability: `git tag cvm-image-v0.3.0-r2 && git push origin cvm-image-v0.3.0-r2`.

The `cvm-image-*` tag does **not** trigger a binary release — `build.yml` fires on `v*` only. It records *which source produced this image*; nothing consumes it.

## Tag Naming Convention

```
v<version>                # e.g. v0.4.0   ← the only tag that builds and releases binaries
contract-v<version>       # e.g. contract-v0.1.0    (TappRegistry implementation)
cvm-image-v<version>      # e.g. cvm-image-v0.3.0-r2 (traceability only, builds nothing)
```

`build.yml` triggers on `v*` and nothing else, so **only a bare `v<version>` tag releases
anything**. The other two prefixes are records, not triggers: pushing them runs no workflow.

There is deliberately no `tapp-server-v*` / `tapp-cli-v*` split. The reproducible build
produces both binaries in a single container run and signs them under one `SHA256SUMS`, so
per-binary tags would require splitting the checksum, the signing loop and the release body
to gain nothing — a binary's version already lives in the binary. See the release workflow
above for how to ship a change to just one of them.

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

### CVM image

The image is a **separate artifact from the binary it carries**, and it is measured: its identity is what remote attestation verifies against. It has no version number of its own — it is identified by the tapp-server version it ships plus a **revision**:

```
<tapp-server version>[-r<image_rev>]      # rev 1 = no suffix: v0.3.0, v0.3.0-r2, v0.3.0-r3 …
```

| Digit | Bump when |
|---|---|
| `<tapp-server version>` | A new tapp-server release goes into the image. Revision restarts at 1. |
| **`-r<N>`** — REVISION | The **image content changed while the binary did not**: kernel, docker/containerd pin, CVM/cryptpilot config, hardening, anything in `cvm/`. |

**Never rebuild a changed image under an identity that is already published.** The image version keys three things at once:

| | example |
|---|---|
| published image name | `og-tdx-dev-grub-v0-3-0-r2` |
| reference values | `verifier/reference-values/gcp/grub/v0.3.0-r2/dev.json` |
| AS policy id | `0g-tapp-gcp-grub-v0.3.0-r2-dev` |

Any change to the image changes its measurements. Reusing the identity makes `register-shared-as.sh` overwrite the reference values behind the **same policy id**, so every node still running the previous image fails verification from that moment on — no deploy, no warning. Bumping the revision leaves the old values registered and gives the new image its own policy.

Consequence to plan for: **verifiers must be told the new policy id** (`verify-app --policy-ids`, plus anywhere ops has one written down). That is the cost of separate identities, and it is much cheaper than a silent fleet-wide verification failure.

Do **not** bump tapp-server just to give a changed image a new number — the binary did not change, and a release whose artifact is byte-identical to the previous one is a lie to everyone reading the version.

Rules that apply to all three binaries/contract:

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
- **Disable unattended apt upgrades in the CVM image** (issue #71 — only `cvm/`
  changed, no crate touched) → **no crate version moves at all**; rebuild the
  image as **`v0.3.0-r2`** (`build-cvm` with `version=v0.3.0`, `image_rev=2`) and
  tag the source commit `cvm-image-v0.3.0-r2`.

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
