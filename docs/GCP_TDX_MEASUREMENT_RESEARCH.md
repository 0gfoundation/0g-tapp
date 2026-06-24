# GCP Confidential VM (Intel TDX) Image Measurement & Verification — Research

**Goal:** measure a GCP confidential image offline and reproducibly into a set of
reference values, publish them, so any third party with (a node's TDX attestation
evidence) + (these reference values) can independently verify the node runs that image.

> **[confirmed]** = verified fact; **[to verify]** = an assumption that must be checked
> against the image or a running node's evidence before relying on it.

---

## 0. TL;DR

- **gce-tcb-verifier endorses only the firmware (MRTD/OVMF launch measurement); it does
  NOT cover the rootfs.** That is why you couldn't find rootfs measurement in it — it
  isn't responsible for the rootfs. [confirmed]
- A confidential VM's trusted measurements are **layered**:
  - **Firmware MRTD** — measured by the hypervisor at TD build time; endorsed by gce-tcb-verifier.
  - **Boot chain RTMR0–2** — shim/grub/kernel/initrd/cmdline, measured by UEFI/grub, landing in the evidence's `uefi_event_logs`.
  - **rootfs integrity** — NOT provided by TDX/GCP itself; the image must do it (dm-verity, or — in this project — folded into the initrd).
  - **Runtime RTMR3** — guest app extensions (tapp `start_app`, etc.).
- Two verification paths: **(A) reuse the CoCo Attestation Service** (Rego policy +
  reference values → EAR token); **(B) standalone with `go-tdx-guest`** (verify the
  quote yourself + compare measurements).

---

## 1. Intel TDX measured boot [confirmed]

| Register | Measured by | Contents |
|---|---|---|
| MRTD | hypervisor at TD build | virtual firmware (OVMF/TDVF). **This is what gce-tcb-verifier endorses.** |
| RTMR0 | firmware | firmware config, UEFI variables (SecureBoot/db/dbx) |
| RTMR1 | firmware → bootloader | shim, grub (`EV_EFI_BOOT_SERVICES_APPLICATION`), GPT |
| RTMR2 | grub | kernel, initrd, kernel cmdline, MokList |
| RTMR3 | guest runtime | tapp `start_app`, cryptpilot FDE, etc. |

- TDX quote (v4/v5) contains MRTD, RTMR0–3, report_data, signed by the PCK cert chain
  (verifiable to the Intel root CA).
- Measurement detail lives in the **cc_eventlog (TCG2)**; the AS parses it into `uefi_event_logs`.

## 2. gce-tcb-verifier: what it does / does not do [confirmed]

[github.com/google/gce-tcb-verifier](https://github.com/google/gce-tcb-verifier) —
"endorsing GCE confidential VM **firmware**".

- Role: computes the launch measurement of the virtual firmware (OVMF) — for TDX this is
  the **MRTD** — and **signs an endorsement** (`LaunchEndorsement`).
- Does **NOT** cover: the boot chain, the **rootfs**, or OS-level integrity.
- Use for us: provides an authoritative reference for the **MRTD** so we don't have to
  reproduce MRTD from OVMF ourselves. Everything else needs another approach.

## 3. Reproducing the boot chain (RTMR0–2) offline [mechanism confirmed / parts to verify]

| Component | Event | Algorithm | Source in image |
|---|---|---|---|
| shim | `EV_EFI_BOOT_SERVICES_APPLICATION` | **Authenticode PE hash** (not a plain file SHA) | ESP `EFI/ubuntu/shimx64.efi` |
| grub | same | same | ESP `EFI/ubuntu/grubx64.efi` |
| kernel | `EV_IPL`, string `/vmlinuz…` | measured by grub | rootfs `/boot/vmlinuz-<ver>` (algo [to verify]) |
| initrd | `EV_IPL`, string `/initrd…` | measured by grub | `/boot/initrd.img-<ver>` |
| kernel_cmdline | `EV_IPL`, string `kernel_cmdline: …` | `SHA-384(cmdline string)` | the `linux` line in grub.cfg |

- The cmdline has **two grub path spellings** (new vs old); compute a SHA-384 for each and
  OR-match in the policy. [confirmed]

## 4. rootfs measurement

- **rootfs integrity is NOT built into TDX/GCP** [confirmed]. A plain writable root
  (cmdline `root=UUID=… ro`) has no rootfs measurement.
- The mainstream approach is **dm-verity**: read-only root + Merkle tree; the root hash is
  passed via the kernel cmdline into RTMR2 (so verifying the cmdline locks the rootfs), or
  measured at runtime into RTMR3. `veritysetup` can compute the root hash offline. [mechanism confirmed]
- **This project: rootfs integrity is folded into the initrd** — so verifying the initrd
  covers the rootfs; the rootfs is not checked separately. [per requirement owner]

## 5. The two verification paths

**A. CoCo AS (current):** the AS verifies the quote signature chain + TCB, parses the
cc_eventlog → EAR token; the decision logic is a Rego policy, reference values live in
RVPS or embedded in the policy. See `verifier/policy.rego`,
`docs/EVIDENCE_AND_AS_VERIFICATION.md`, `src/verify.rs` (`tapp-cli verify-app`).

**B. Standalone (go-tdx-guest):** verify the quote yourself (PCK→Intel root, TCB), check
MRTD against the gce-tcb-verifier endorsement, replay the cc_eventlog to compare the boot
chain, and validate the rootfs. Libraries: [go-tdx-guest](https://github.com/google/go-tdx-guest),
[go-sev-guest](https://github.com/google/go-sev-guest), gce-tcb-verifier.

## 6. Registration mechanism (against the remote gRPC AS `47.237.201.184`) [confirmed]

- **Policy → AS `SetAttestationPolicy(policy_id, policy)`**, port 50004. `policy` =
  **base64url-no-pad of the Rego text**. **Measured: no authentication — anyone who can
  reach :50004 can register/overwrite any policy_id.**
- **Reference values → RVPS `RegisterReferenceValue(message)`** (`reference.proto`),
  `message` = `{"version","type":"sample","payload":<base64 reference JSON>}`.
  **Measured: RVPS port 50003 is not externally reachable** → use "reference values
  embedded in the policy" instead, no RVPS dependency.
- Overall `ear.status==affirming` also depends on `hardware` (platform TCB). Current nodes
  report `tcb_status=OutOfDate` → ops must update the platform TCB, otherwise the overall
  status will not be affirming (but `executables==3` can still indicate the boot chain matched).

## 7. Real uefi_event_logs format on GCP [confirmed, measured on 6.17.0-1018-gcp]

| Component | `type_name` | Match condition | Sample digest |
|---|---|---|---|
| shim | `EV_EFI_BOOT_SERVICES_APPLICATION` | `details.device_paths` contains `File(\EFI\ubuntu\shimx64.efi)` | `4637fb5c…` |
| grub | same | `device_paths` contains `grubx64.efi` | `d9c40784…` |
| kernel | `EV_IPL` | `details.string` starts with `/vmlinuz` | `34d6ebfb…` |
| initrd | `EV_IPL` | `details.string` starts with `/initrd` | `b7b49c3a…` |
| kernel_cmdline | `EV_IPL` | `details.string` starts with `kernel_cmdline:` | `7dd3d3d1…` |

- digest is in `digests[_].digest` (hex), alg = `"SHA-384"`.
- ⚠️ The old `0g-tapp-verifier/policy.rego` matched kernel/initrd by `"Kernel"/"Initrd"`
  (capitalized — TDVF direct kernel load). **GCP uses lowercase paths `/vmlinuz`/`/initrd`,
  so that must change.** The actual cmdline prefix is `kernel_cmdline:` (not the
  `grub_kernel_cmdline` label seen in reference dumps). No cryptpilot events on GCP.

## 8. Action checklist

1. Unpack the target image → compute shim/grub (Authenticode) + kernel/initrd (file hash) +
   cmdline, and reconcile against a running node's evidence (confirm the algorithm assumptions).
2. Use the gce-tcb-verifier endorsement for MRTD.
3. Fill the reference values into `verifier/policy.rego`, register via
   `SetAttestationPolicy(policy_id="0g-tapp")`.
4. Run `AttestationEvaluate(policy_ids:["0g-tapp"])` until `executables==3`.

## 9. References

- gce-tcb-verifier: https://github.com/google/gce-tcb-verifier
- go-tdx-guest: https://github.com/google/go-tdx-guest
- go-sev-guest: https://github.com/google/go-sev-guest
- dm-verity: https://docs.kernel.org/admin-guide/device-mapper/verity.html
- veritysetup(8): https://manpages.opensuse.org/Tumbleweed/cryptsetup-doc/veritysetup.8.en.html
- CoCo AS policy docs: https://github.com/confidential-containers/trustee/blob/main/attestation-service/docs/policy.md
- Intel TDX: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html
