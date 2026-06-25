package policy

import rego.v1

# =============================================================================
# 0g-tapp boot-chain verification policy (canonical, tapp-level)
# =============================================================================
# Verifies a TDX confidential VM boot chain (shim / grub / kernel / initrd /
# kernel_cmdline) against an image's reference values. These measurements come from
# the TDX evidence's uefi_event_logs (RTMR0-2). rootfs integrity is folded into the
# initrd, so it is not checked separately.
#
# ONE canonical policy — image-/version-/env-agnostic. What differs per
# release × {dev,prod} is the REFERENCE VALUES, NOT this logic. The values are NOT
# baked in here; they are read from RVPS via the query_reference_value() builtin under
# the "measurement.<component>.SHA-384" keys. See reference-values/<version>/<env>.json.
#
# How the reference values reach the AS (two verification methods, same policy):
#   * Self-hosted AS (RVPS writable): register the image's reference-values json to
#     RVPS; this policy reads them via query_reference_value(). See 0g-tapp-verifier.
#   * Shared AS (RVPS not writable): inject the values into a copy of this policy at
#     registration time and register it under a per-release/env id, e.g.
#     0g-tapp-<version>-<env> (the _cpu device-class suffix is appended by the AS).
#
# uefi_event_logs field formats (measured on a cryptpilot image, kernel 6.17.0-1018-gcp):
#   shim   : type_name=EV_EFI_BOOT_SERVICES_APPLICATION, details.device_paths contains "shimx64.efi"
#   grub   : type_name=EV_EFI_BOOT_SERVICES_APPLICATION, details.device_paths contains "grubx64.efi"
#   kernel         : type_name=EV_IPL, details.string starts with "/vmlinuz"
#   initrd         : type_name=EV_IPL, details.string starts with "/initrd"
#   kernel_cmdline : type_name=EV_IPL, details.string starts with "kernel_cmdline:"
#   digest is in .digests[_].digest (hex), alg = "SHA-384"

# --- Reference values: from RVPS only (no baked-in values) ------------------
# query_reference_value() returns null when the key is absent → treated as empty.
qrv(key) := v if {
	v := query_reference_value(key)
	v != null
}

qrv(key) := [] if query_reference_value(key) == null

ref_shim := {x | some x in qrv("measurement.shim.SHA-384")}

ref_grub := {x | some x in qrv("measurement.grub.SHA-384")}

ref_kernel := {x | some x in qrv("measurement.kernel.SHA-384")}

ref_initrd := {x | some x in qrv("measurement.initrd.SHA-384")}

# kernel_cmdline may have several allowed values (grub path spellings); OR-match.
ref_kernel_cmdline := {x | some x in qrv("measurement.kernel_cmdline.SHA-384")}

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
