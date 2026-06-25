# 0g-tapp boot-chain verification policy

Verifies that a confidential VM (Intel TDX) node's boot-chain measurements match a
known-good image. Used with the CoCo Attestation Service (CoCo-AS, gRPC `:50004`).

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
- **kernel_cmdline is multi-value OR**: list several in `ref_kernel_cmdline`, any match passes.
- **rootfs is not checked separately**: its integrity is folded into the initrd, so
  verifying the initrd covers it.

> The field formats above were measured from real evidence of a cryptpilot image
> (kernel `6.17.0-1018-gcp`). The scheme is cryptpilot's and is platform-agnostic.

## Reference values

Reference values are **embedded in `policy.rego`** (`ref_shim`/`ref_grub`/`ref_kernel`/
`ref_initrd`/`ref_kernel_cmdline`) — no RVPS dependency, so a third party can reproduce
the check with just this policy. Update these constant sets when the image changes.

> The values currently in `policy.rego` are **samples** measured from one `6.17.0-1018-gcp`
> node; confirm/replace per the target release before publishing (initrd varies per image).

## Register with the AS

```bash
AS=47.237.201.184:50004
PROTO_DIR=path/to/protos        # contains attestation.proto
POLICY_B64=$(base64 -w0 policy.rego | tr '+/' '-_' | tr -d '=')   # base64url no-pad
grpcurl -plaintext -import-path "$PROTO_DIR" -proto attestation.proto \
  -d '{"policy_id":"0g-tapp","policy":"'"$POLICY_B64"'"}' \
  "$AS" attestation.AttestationService/SetAttestationPolicy
```

Evaluate:

```bash
# evidence as base64url-no-pad → AttestationEvaluate(policy_ids=["0g-tapp"])
grpcurl -plaintext -import-path "$PROTO_DIR" -proto attestation.proto \
  -d '{"verification_requests":[{"tee":"tdx","evidence":"<b64url>"}],"policy_ids":["0g-tapp"]}' \
  "$AS" attestation.AttestationService/AttestationEvaluate
# read the EAR token submods.cpu0: executables==3 means the boot chain matched
```

## Notes (measured findings)

- **`SetAttestationPolicy` has no auth**: anyone who can reach `:50004` can register or
  overwrite any `policy_id` (measured). So a policy on a shared AS cannot be the sole root
  of trust — a verifier should carry this policy itself (self-contained reference values)
  or trust the AS operator.
- **RVPS (`:50003`) is not externally reachable** — hence reference values are embedded in
  the policy rather than using `query_reference_value`.
- **Overall `ear.status`**: `executables==3` only means the boot chain matched;
  `ear.status==affirming` also needs `hardware` (affected by platform `tcb_status`) etc.
  Current nodes report `tcb_status=OutOfDate` → ops must update the platform TCB, otherwise
  the overall status will not be affirming.

See `docs/TDX_BOOT_CHAIN_VERIFICATION.md` for the measurement background (cryptpilot-fde
reference values, platform-agnostic).
