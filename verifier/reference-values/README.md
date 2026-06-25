# Reference values

Boot-chain reference values (shim / grub / kernel / initrd / kernel_cmdline) for verifying
a TDX confidential node against a known-good image, consumed by `verifier/policy.rego`.

## Layout

```
verifier/reference-values/<tapp-server-version>/<env>.json   # env ∈ {dev, prod}
```

- **One set per tapp-server release × environment**, starting at **v0.1.0**. Each release
  ships a specific image; its boot-chain digests are fixed → one reference set.
- **dev and prod images differ** → separate `dev.json` / `prod.json` per version.
- The policy (`verifier/policy.rego`) is a single, canonical, image-agnostic logic; only
  these values vary. See that file's header for the two verification methods.

## Generating (manual)

Values are produced from the release image with cryptpilot — **must run on an Alinux host**
(`cryptpilot-convert` / `cryptpilot-fde` are Alinux-only), so this is **not** automated in CI:

```bash
cryptpilot-fde show-reference-value --disk <release-image>
# → kernel / initrd / grub / shim / kernel_cmdline digests
```

Put the output into `verifier/reference-values/<version>/<env>.json` keyed by
`measurement.<component>.SHA-384` (kernel_cmdline may list multiple allowed values).

## Using

- **Self-hosted AS** (RVPS writable): register the json to RVPS; the policy reads it via
  `query_reference_value()`. See the `../0g-tapp-verifier/` submodule (`tdx-boot-chain/`).
- **Shared AS** (RVPS not writable): inject the json into the policy at registration —
  `verifier/register-shared-as.sh <version> <env> <as-endpoint>` registers it as
  `0g-tapp-<version>-<env>`.
