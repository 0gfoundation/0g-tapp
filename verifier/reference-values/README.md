# Reference values

Boot-chain reference values (`shim / grub / kernel / initrd / kernel_cmdline` for a grub image,
`uki` for a UKI one) for verifying a TDX confidential node against a known-good image, consumed by
`verifier/policy.rego`.

## Layout

```
canonical: verifier/reference-values/<boot_format>/<version>/<env>.json
custom:    verifier/reference-values/<boot_format>/<version>/<env>/<owner>.json
#   boot_format ∈ {grub, uki}; env ∈ {dev, prod}
#   owner (custom mode only): 0x-stripped, lowercased OWNER_ADDRESS
```

- **One set per boot_format × tapp-server release × environment × owner.** Each combination
  ships a specific image; its boot-chain digests are fixed → one reference set per combination.
- **cloud is NOT a dimension.** One image serves every platform: a single HWE generic kernel
  (≥6.16, for the TDX RTMR measurement interface) instead of a per-cloud one, and the dev
  variant's SSH access baked in at build time (`DEV_SSH_PUBKEY`) instead of injected at boot by
  `google-guest-agent` / `cloud-init`. So the same build boots on GCP, Alibaba Cloud and bare
  metal with identical measurements, and `cloud` now only picks where Stage C publishes it.
  Verified on real GCP TDX hardware with `6.17.0-42-generic`: boots, gve/GVNIC brings up `ens3`,
  RTMR extend works, and the node's live `measurement.uki` equals the one extracted offline.
- **boot_format is a dimension**: the boot chain differs by format → the **measurement shape** differs
  (grub → 5 components `shim/grub/kernel/initrd/kernel_cmdline`; uki → 1 `measurement.uki`). Without it,
  a grub and a uki image for the same version/env/owner would collide on the path + AS policy id.

- **dev and prod images differ** (HARDEN=0 / HARDEN=1) → separate `dev/` / `prod/` per version.
- **owner is a dimension only in custom builds**. Canonical images (the default,
  `BUILD_MODE=canonical`) are owner-agnostic: owner/chain/kbs are claimed at runtime via the
  ClaimConfig RPC and land in the **runtime measurement event log** (a `claim_config` event,
  like `start_app`), NOT in the boot-chain digests — one image ⇒ one reference set at
  `<env>.json`, no owner path segment at all. Verifiers get the owner from the claim_config
  event in the evidence and reconcile it against the on-chain registration.
  Custom builds bake `OWNER_ADDRESS` into `/etc/tapp/config.toml`, folding the owner into
  `measurement.initrd.SHA-384` → per-owner reference sets at `<env>/<owner>.json`.
- The policy (`verifier/policy.rego`) is a single, canonical, image-agnostic logic; only
  these values vary. See that file's header for the two verification methods.

### Older layouts — kept, never written again
Two earlier layouts remain in this directory so that images built under them, and the nodes still
running those images, keep verifying. Nothing writes to them any more; **do not tidy them away**
until no node runs an image of that era.

| Era | Path | Policy id |
|---|---|---|
| current | `<boot_format>/<version>/<env>.json` | `0g-tapp-<boot_format>-<version>-<env>` |
| had a cloud dimension | `<cloud>/<boot_format>/<version>/<env>.json` | `0g-tapp-<cloud>-<boot_format>-<version>-<env>` |
| oldest, flat (≤ v0.1.0) | `<version>/<env>.json` | — |

They cannot be confused for one another: the first path segment is `grub`/`uki` today and was
`gcp`/`ali` before, and those sets do not overlap.

## Generating

Values are produced from the release image with cryptpilot — **must run on an Alinux host**
(`cryptpilot-convert` / `cryptpilot-fde` are Alinux-only). `show-reference-value` needs a
**#128-fixed cryptpilot-fde** (stock 0.7.0 errors `saved_entry not found` on a never-booted
image); it's provided by `cvm/ci/setup-toolchain.sh` (installs released 0.8.0 + overlays the
#128 `cryptpilot-fde-host`). The tool emits JSON with the `measurement.<component>.SHA-384` keys directly.

Automated on the al8 self-hosted runner (`.github/workflows/build-cvm.yml`); manual equivalent:

```bash
cvm/ci/setup-toolchain.sh                                  # provision the 0.8.0 + #128/#130 toolchain once
cvm/ci/gen-reference-values.sh \
  <release-image> <boot_format> <version> <env> <owner>   # writes <boot_format>/<version>/<env>/<owner>.json
```

## Using

- **Self-hosted AS** (RVPS writable): register the json to RVPS; the policy reads it via
  `query_reference_value()`. See the `../0g-tapp-verifier/` submodule (`tdx-boot-chain/`).
- **Shared AS** (RVPS not writable): inject the json into the policy at registration —
  `verifier/register-shared-as.sh <boot_format> <version> <env> <owner> [as-endpoint]` registers it as
  `0g-tapp-<boot_format>-<version>-<env>-<owner>`.
