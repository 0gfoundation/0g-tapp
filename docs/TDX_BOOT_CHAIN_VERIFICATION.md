# TDX Confidential VM Boot-Chain Measurement & Verification

**Goal:** verify that a TDX confidential VM node runs a known-good image, by checking its
boot-chain measurements (shim / grub / kernel / initrd / kernel_cmdline) against reference
values produced from that image.

**The mechanism is [cryptpilot](https://github.com/openanolis/cryptpilot)'s and is
platform-agnostic** — the same scheme is used regardless of cloud (Aliyun, GCP, …). The
cloud a node happens to run on is irrelevant to this verification.

> Note: older cryptpilot used a different scheme (AAEL events like
> `cryptpilot.alibabacloud.com fde_rootfs_hash` extended into RTMR3). Current cryptpilot
> uses the boot-chain `uefi_event_logs` scheme described here. It is the cryptpilot
> version, not the platform, that determines the scheme.

---

## 0. TL;DR

- The confidential image is produced by **`cryptpilot-convert`** (adds FDE / dm-verity).
- Reference values for the 5 boot-chain components come from
  **`cryptpilot-fde show-reference-value --disk <image>`** — one command, reproducible
  from the image (a third party can re-run it on the same image and get the same values).
- rootfs integrity = **`cryptpilot-verity`** (dm-verity), folded into the boot chain, so
  it is not verified separately.
- A node's TDX evidence carries these measurements in `uefi_event_logs` (RTMR0-2). Verify
  via a CoCo Attestation Service + a Rego policy that compares them to the reference values.

---

## 1. cryptpilot components

| Component | Role |
|---|---|
| `cryptpilot-convert` | converts a base image into an FDE/verity-protected confidential image |
| `cryptpilot-fde` | FDE boot path (grub etc.); `show-reference-value --disk <img>` produces the boot-chain reference values |
| `cryptpilot-verity` | dm-verity protection for the rootfs |

## 2. TDX measured-boot registers (context)

| Register | Measured by | Contents |
|---|---|---|
| MRTD | hypervisor at TD build | virtual firmware (OVMF/TDVF) |
| RTMR0 | firmware | firmware config, UEFI variables |
| RTMR1 | firmware → bootloader | shim, grub |
| RTMR2 | grub | kernel, initrd, kernel cmdline |
| RTMR3 | guest runtime | tapp `start_app`, etc. |

The boot-chain measurements we verify (shim/grub/kernel/initrd/cmdline) live in RTMR0-2 and
are detailed in the **cc_eventlog (TCG2)**, which the AS parses into `uefi_event_logs`.

## 3. The 5 boot-chain measurements in the evidence

Confirmed `uefi_event_logs` format (measured on a cryptpilot image, kernel `6.17.0-1018-gcp`):

| Component | `type_name` | Match condition |
|---|---|---|
| shim | `EV_EFI_BOOT_SERVICES_APPLICATION` | `details.device_paths` contains `shimx64.efi` |
| grub | `EV_EFI_BOOT_SERVICES_APPLICATION` | `details.device_paths` contains `grubx64.efi` |
| kernel | `EV_IPL` | `details.string` starts with `/vmlinuz` |
| initrd | `EV_IPL` | `details.string` starts with `/initrd` |
| kernel_cmdline | `EV_IPL` | `details.string` starts with `kernel_cmdline:` |

digest is in `digests[_].digest` (hex), alg `SHA-384`. kernel_cmdline may have multiple
allowed values (grub path spellings) — OR-match.

## 4. Reference values — produced by cryptpilot-fde (reproducible)

```bash
cryptpilot-fde show-reference-value --disk <image>
# → reference values for kernel / initrd / grub / shim / kernel_cmdline
```

This is the authoritative, **reproducible** source: anyone with the same image gets the
same values — no need to trust a running node. (cryptpilot
[PR #128](https://github.com/openanolis/cryptpilot/pull/128) makes this work on
never-booted images by falling back to GRUB's default menuentry when `grubenv` has no
`saved_entry`.)

Output is keyed `measurement.<component>.SHA-384`. Because `cryptpilot-convert` /
`cryptpilot-fde` only run on an Alinux host, generation is **manual, not CI-automated**.

The values are checked into this repo under
[`verifier/reference-values/<tapp-server-version>/<env>.json`](../verifier/reference-values/) — **one set per
tapp-server release × environment** (`dev`/`prod` images differ), starting at `v0.1.0`. See
that directory's README. The policy itself is image-/version-/env-agnostic; only these
values vary.

## 5. Verification — CoCo-AS + Rego policy

The AS verifies the TDX quote signature chain + TCB and parses the cc_eventlog; a Rego
policy compares the 5 boot-chain measurements from `uefi_event_logs` against the reference
values and sets the AR4SI `executables` claim (3 = matched).

- Policy: `verifier/policy.rego` (this repo) — a **single canonical, image-/version-/env-agnostic**
  policy. It reads reference values from RVPS via the AS `query_reference_value()` builtin;
  no values are baked in.
- **Two verification methods, same policy** — they differ only in how the reference values
  reach the AS:
  - **Self-hosted AS** (`coco-as-grpc` + `rvps`, RVPS writable): register the release's
    `verifier/reference-values/<version>/<env>.json` to RVPS → policy reads via `query_reference_value()`.
    The full stack is vendored as a git submodule at `verifier/0g-tapp-verifier/`
    (`tdx-boot-chain/`; upstream
    [`0g-tapp-verifier`](https://github.com/0gfoundation/0g-tapp-verifier)). Pull it with
    `git submodule update --init verifier/0g-tapp-verifier`.
  - **Shared remote AS** (RVPS not writable): inject the values into a copy of the policy at
    registration time, registered under id `0g-tapp-<version>-<env>` —
    `verifier/register-shared-as.sh <version> <env> [as-endpoint]`.
- Client: `tapp-cli verify-app --as-endpoint <as>:50004 --policy-ids 0g-tapp-<version>-<env>`
  (e.g. `0g-tapp-v0.1.0-dev`).

## 6. rootfs

rootfs integrity is protected by `cryptpilot-verity` (dm-verity) and folded into the boot
chain, so verifying the boot chain (incl. initrd) covers it — no separate rootfs check.

## 7. References

- cryptpilot: https://github.com/openanolis/cryptpilot
- cryptpilot PR #128 (reference-value extraction on never-booted images): https://github.com/openanolis/cryptpilot/pull/128
- CoCo AS policy docs: https://github.com/confidential-containers/trustee/blob/main/attestation-service/docs/policy.md
- dm-verity: https://docs.kernel.org/admin-guide/device-mapper/verity.html
- Intel TDX: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
- This repo: `verifier/policy.rego`, `tapp-common/src/verify.rs` (`tapp-cli verify-app`)
