# Reference values

Boot-chain reference values (shim / grub / kernel / initrd / kernel_cmdline) for verifying
a TDX confidential node against a known-good image, consumed by `verifier/policy.rego`.

## Layout

```
verifier/reference-values/<cloud>/<tapp-server-version>/<env>/<owner>.json   # cloud ∈ {gcp, ali}; env ∈ {dev, prod}; owner = OWNER_ADDRESS (lowercased)
```

- **One set per cloud × tapp-server release × environment × owner.** Each combination ships a
  specific image; its boot-chain digests are fixed → one reference set per (cloud, version, env, owner).
- **cloud is a dimension**: each cloud builds its **own** image (e.g. GCP uses `linux-image-gcp` +
  gVNIC + GCP-specific boot fixes; Alibaba Cloud uses its own kernel/drivers), so the boot-chain
  digests genuinely differ per cloud ⇒ distinct reference sets and distinct AS policies. Without it,
  clouds would collide on the shared repo path and the shared AS policy id.
- **dev and prod images differ** (HARDEN=0 / HARDEN=1) → separate `dev/` / `prod/` per version.
- **owner is a dimension**: `OWNER_ADDRESS` is baked into `/etc/tapp/config.toml` on the verity
  rootfs, and `policy.rego` folds rootfs integrity into the **initrd** measurement, so a
  different owner ⇒ a different `measurement.initrd.SHA-384` ⇒ a distinct reference set.
- The policy (`verifier/policy.rego`) is a single, canonical, image-agnostic logic; only
  these values vary. See that file's header for the two verification methods.

## Generating

Values are produced from the release image with cryptpilot — **must run on an Alinux host**
(`cryptpilot-convert` / `cryptpilot-fde` are Alinux-only). `show-reference-value` needs a
**#128-fixed cryptpilot-fde** (stock 0.7.0 errors `saved_entry not found` on a never-booted
image); it's provided by `gcp-cvm/ci/setup-toolchain.sh` (installs released 0.8.0 + overlays the
#128 `cryptpilot-fde-host`). The tool emits JSON with the `measurement.<component>.SHA-384` keys directly.

Automated on the al8 self-hosted runner (`.github/workflows/build-cvm.yml`); manual equivalent:

```bash
gcp-cvm/ci/setup-toolchain.sh                                  # provision the 0.8.0 + #128/#130 toolchain once
gcp-cvm/ci/gen-reference-values.sh \
  <release-image> <cloud> <version> <env> <owner>              # writes <cloud>/<version>/<env>/<owner>.json
```

## Using

- **Self-hosted AS** (RVPS writable): register the json to RVPS; the policy reads it via
  `query_reference_value()`. See the `../0g-tapp-verifier/` submodule (`tdx-boot-chain/`).
- **Shared AS** (RVPS not writable): inject the json into the policy at registration —
  `verifier/register-shared-as.sh <cloud> <version> <env> <owner> [as-endpoint]` registers it as
  `0g-tapp-<cloud>-<version>-<env>-<owner>`.
