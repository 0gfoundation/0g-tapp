# 0g-tapp boot-chain verification policy

Verifies that a confidential VM (Intel TDX) node's boot-chain measurements match a
known-good release image. Used with the CoCo Attestation Service (CoCo-AS, gRPC `:50004`).

`policy.rego` here is the **single canonical policy** — one logic for all releases,
images, and environments. What differs per release × environment is the **reference
values**, kept under [`reference-values/`](./reference-values/), not this file.

## What it checks

Only the 5 boot-chain measurements (from the TDX evidence's `uefi_event_logs`, covered
by RTMR0-2):

| Component | How it is identified in uefi_event_logs |
|---|---|
| shim | `EV_EFI_BOOT_SERVICES_APPLICATION` · `details.device_paths` contains `shimx64.efi` |
| grub | `EV_EFI_BOOT_SERVICES_APPLICATION` · `details.device_paths` contains `grubx64.efi` |
| kernel | `EV_IPL` · `details.string` starts with `/vmlinuz` |
| initrd | `EV_IPL` · `details.string` starts with `/initrd` |
| kernel_cmdline | `EV_IPL` · `details.string` starts with `kernel_cmdline:` |

- digest is in `digests[_].digest` (hex), alg `SHA-384`.
- **kernel_cmdline is multi-value OR**: a reference set may list several allowed values
  (grub path spellings); any match passes.
- **rootfs is not checked separately**: its integrity is folded into the initrd, so
  verifying the initrd covers it.

> The scheme is cryptpilot's measured-boot layout and is platform-agnostic (Alibaba Cloud,
> GCP, …). Field formats above were measured from real evidence of a cryptpilot image.

## Reference values

The policy reads reference values from RVPS via the `query_reference_value()` builtin
under `measurement.<component>.SHA-384` keys — **no values are baked into `policy.rego`**.

The values themselves live in [`reference-values/<version>/<env>.json`](./reference-values/),
one set per tapp-server release × `{dev,prod}` (see that directory's README for layout and
how to (re)generate them with `cryptpilot-fde` on an Alinux host).

## Two verification methods (same policy)

### 1. Self-hosted AS (RVPS writable)

Register the release's `reference-values/<version>/<env>.json` into your own RVPS, then use
`policy.rego` unchanged; it reads the values via `query_reference_value()`. The full
self-hosted stack (coco-as-grpc + rvps + compose + run script) is vendored in as a git
submodule at [`0g-tapp-verifier/`](./0g-tapp-verifier) (upstream:
[`0g-tapp-verifier`](https://github.com/0gfoundation/0g-tapp-verifier),
`tdx-boot-chain/`). Pull it with:

```bash
git submodule update --init verifier/0g-tapp-verifier   # or clone --recursive
```

### 2. Shared AS (RVPS not writable)

The shared AS's RVPS cannot be written externally, so values are **injected into a copy of
the policy** at registration time and registered under a per-release/env id:

```bash
./verifier/register-shared-as.sh v0.1.0 dev            # → policy id 0g-tapp-v0.1.0-dev
./verifier/register-shared-as.sh v0.1.0 dev 34.171.164.181:50004
# gated AS (issue #82): the write needs a key; reads (AttestationEvaluate /
# GetAttestationChallenge) stay open. Unset = unchanged, and an ungated AS ignores the header.
AS_WRITE_KEY=<key> ./verifier/register-shared-as.sh v0.1.0 dev
```

Keys are issued against the registry's on-chain `admin` signature, expire (30d / 90d / never) and can be revoked. In CI the key comes from the `AS_WRITE_KEY` repository secret. Note what a key does **not** buy: an EAR token records the policy *id* it evaluated, never a hash of the policy, so a write made with a stolen key is as undetectable to verifiers as one made against an open port — the key makes writes attributable and revocable, not verifiable.

Then evaluate (the AS appends the `_cpu` device-class suffix internally):

```bash
tapp-cli verify-app --app-id <id> \
  --as-endpoint 34.171.164.181:50004 \
  --policy-ids 0g-tapp-v0.1.0-dev
# executables==3 in the EAR token's cpu submod means the boot chain matched
```

## Notes (measured findings)

- **`SetAttestationPolicy` has no auth**: anyone who can reach `:50004` can register or
  overwrite any `policy_id`. A policy on a shared AS is therefore not a sole root of trust;
  for the strongest guarantee run a self-hosted AS (method 1) you control.
- **Overall `ear.status`**: `executables==3` only means the boot chain matched;
  `ear.status==affirming` also needs `hardware` (affected by platform `tcb_status`) etc.
  If a node reports `tcb_status=OutOfDate`, ops must update the platform TCB, otherwise
  the overall status will not be affirming.

See [`../docs/TDX_BOOT_CHAIN_VERIFICATION.md`](../docs/TDX_BOOT_CHAIN_VERIFICATION.md) for
the measurement background (cryptpilot-fde reference values, platform-agnostic).
