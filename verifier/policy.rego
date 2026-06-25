package policy

import rego.v1

# =============================================================================
# 0g-tapp boot-chain verification policy (policy_id = "0g-tapp")
# =============================================================================
# Verifies a confidential VM (Intel TDX) boot-chain measurement against the
# reference values of a known-good image:
#   shim / grub / kernel / initrd / kernel_cmdline
# These measurements come from the TDX evidence's uefi_event_logs (RTMR0-2).
# rootfs integrity is folded into the initrd, so it is not checked separately.
#
# Reference values are EMBEDDED in this file (no RVPS dependency; self-contained,
# third-party reproducible).
#
# Register with the CoCo Attestation Service:
#   POLICY=$(base64 -w0 policy.rego | tr '+/' '-_' | tr -d '=')   # base64url no-pad
#   grpcurl -plaintext -import-path <protos> -proto attestation.proto \
#     -d '{"policy_id":"0g-tapp","policy":"'"$POLICY"'"}' \
#     <AS>:50004 attestation.AttestationService/SetAttestationPolicy
# Then AttestationEvaluate(policy_ids:["0g-tapp"]) uses this policy.
#
# uefi_event_logs field formats (measured on GCP Ubuntu 6.17.0-1018-gcp):
#   shim   : type_name=EV_EFI_BOOT_SERVICES_APPLICATION, details.device_paths contains "shimx64.efi"
#   grub   : type_name=EV_EFI_BOOT_SERVICES_APPLICATION, details.device_paths contains "grubx64.efi"
#   kernel         : type_name=EV_IPL, details.string starts with "/vmlinuz"
#   initrd         : type_name=EV_IPL, details.string starts with "/initrd"
#   kernel_cmdline : type_name=EV_IPL, details.string starts with "kernel_cmdline:"
#   digest is in .digests[_].digest (hex), alg = "SHA-384"

# --- Reference values (SHA-384, hex) ---------------------------------------
# Two sources, RVPS takes priority, embedded is the fallback:
#   * RVPS path (local self-hosted trustee): register values under the
#     "measurement.<component>.SHA-384" keys; the policy reads them via the AS-injected
#     query_reference_value() builtin and they override the embedded defaults below.
#   * Embedded path (shared remote AS where RVPS is not writable): the values below
#     are used directly, so the policy is self-contained.
# Same policy works for both. Update these for the target release image.
embedded_shim := {
	"4637fb5cd30847e5f09ae24f8a50ce1611c4d21afd0ecb69c8ec40bc82dc11bc48abda1f8044fe340bfb70b29606eb47",
}

embedded_grub := {
	"d9c40784e214bb829477f46245758e74f6b145dbf012960d4053c2fe27545738d89833297b4fd9ec348dde75910bfa33",
}

embedded_kernel := {
	"34d6ebfb021bfa10edc6e925fa3d93606a8d9da6c97d331ec936fd4c36dc5cf34a154f6405ee1a84e5568f02ee93ccca",
}

embedded_initrd := {
	"311a57077c4490adfe3c7605da9f1dd809df3bcfa059803d70c2c43bf9b6dc6907aa3b03145adb5f91f5f6e89a69a6d9",
}

# kernel_cmdline may have several allowed values (new/old grub path spellings);
# matching any one is enough (OR).
embedded_kernel_cmdline := {
	"7dd3d3d1ddb00dda05d63676ff8759bd82b933ce930fa13deb811fa4faa09604f6b029aea4f98dabf23675d91162ea19",
	"bad43ebbd92a8dde1d5b4198cff9cc268e93b771a402fbfe14718879bbb5735a1fd095c98f06d276509ae354805971e5",
}

# RVPS values for a key as a set, read via the AS-injected query_reference_value()
# builtin (returns null when the key is absent → treated as empty).
qrv(key) := v if {
	v := query_reference_value(key)
	v != null
}

qrv(key) := [] if query_reference_value(key) == null

rvps_set(key) := {x | some x in qrv(key)}

# Use RVPS values when present, else the embedded fallback.
pick(key, fallback) := rvps_set(key) if count(rvps_set(key)) > 0

pick(key, fallback) := fallback if count(rvps_set(key)) == 0

ref_shim := pick("measurement.shim.SHA-384", embedded_shim)

ref_grub := pick("measurement.grub.SHA-384", embedded_grub)

ref_kernel := pick("measurement.kernel.SHA-384", embedded_kernel)

ref_initrd := pick("measurement.initrd.SHA-384", embedded_initrd)

ref_kernel_cmdline := pick("measurement.kernel_cmdline.SHA-384", embedded_kernel_cmdline)

# --- Extract component digests from uefi_event_logs ------------------------
# Digests of EV_EFI_BOOT_SERVICES_APPLICATION events whose device_paths contain `needle`.
bsa_digests(needle) := {d |
	some e in input.tdx.uefi_event_logs
	e.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	some p in e.details.device_paths
	contains(p, needle)
	d := e.digests[_].digest
}

# Digests of EV_IPL events whose details.string starts with `prefix`.
ipl_digests(prefix) := {d |
	some e in input.tdx.uefi_event_logs
	e.type_name == "EV_IPL"
	startswith(e.details.string, prefix)
	d := e.digests[_].digest
}

# Non-empty intersection = a measured digest matched a reference value.
hit(measured, reference) if {
	some m in measured
	m in reference
}

boot_chain_ok if {
	hit(bsa_digests("shimx64.efi"), ref_shim)
	hit(bsa_digests("grubx64.efi"), ref_grub)
	hit(ipl_digests("/vmlinuz"), ref_kernel)
	hit(ipl_digests("/initrd"), ref_initrd)
	hit(ipl_digests("kernel_cmdline:"), ref_kernel_cmdline)
}

# --- AR4SI trust claims ----------------------------------------------------
# executables=3: "only a recognized set of approved executables was loaded".
# This is the core conclusion of this policy.
default executables := 33

executables := 3 if boot_chain_ok

# hardware: basic check that this is an Intel-signed TDX quote. Note the overall
# ear.status still depends on TCB — if tcb_status != UpToDate, ops must update the
# platform TCB or the hardware claim will not be affirming.
default hardware := 97

hardware := 2 if {
	input.tdx
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.tcb_status == "UpToDate"
}

default configuration := 36

configuration := 2 if {
	input.tdx
	input.tdx.td_attributes.debug == false
}

trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"instance-identity": 0,
	"file-system": 0,
	"runtime-opaque": 0,
	"storage-opaque": 0,
	"sourced-data": 0,
}
