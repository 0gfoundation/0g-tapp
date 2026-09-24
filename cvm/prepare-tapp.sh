#!/bin/bash
# prepare-tapp.sh <input-base.qcow2> <output-tapp.qcow2>
#
# Turn an Ubuntu base image into a working cryptpilot tapp image.
# Chains four steps, two of which are the key fixes:
#   [kernel swap] install the HWE generic kernel (optional, when INSTALL_KERNEL=1) -- >=6.16,
#           for the TDX RTMR measurement interface. One kernel for every platform; see [1/4].
#   [fix A] point the /boot/vmlinuz symlink at that kernel -- so convert builds the
#           cryptpilot-enabled initrd for the correct kernel
#           (otherwise: read-only rootfs / RTMR not extended / verity bypassed)
#   [convert] cryptpilot-convert (auto-sets TMPDIR=/tmp to avoid dracut failing in chroot)
#   [fix B] sync the boot-partition grub.cfg + modules to the ESP -- fixes the grub boot
#           crash (bli.mod / vmlinuz not found)
#
# By default does not modify the input image (works on a copy).

set -euo pipefail

# ===== Tunables =====
# BOOT_FORMAT is the only dimension that changes the image (each image = one boot format = one
# measurement chain):
#   BOOT_FORMAT grub | uki — boot format. grub: traditional shim/grub (convert #130 syncs the ESP
#               grub.cfg); uki: systemd-boot / Unified Kernel Image (convert --uki; needs dracut +
#               systemd-boot-efi). Reference value differs: grub -> 5 components, uki -> 1 (measurement.uki).
# CLOUD no longer selects a kernel -- one HWE generic kernel serves every platform (see [1/4]). It
# survives only to pick the Stage C publish target and, with grub, whether the ESP verify below can
# run; the image itself is identical whatever it is set to.
CLOUD="${CLOUD:-gcp}"
BOOT_FORMAT="${BOOT_FORMAT:-grub}"
CONFIG_DIR="${CONFIG_DIR:-./config_dir}"
FDE_PACKAGE="${FDE_PACKAGE:-cryptpilot-fde_0.7.0_amd64.deb}"
ROOTFS_MODE="${ROOTFS_MODE:---rootfs-no-encryption}"   # or "--rootfs-passphrase <pass>"
INSTALL_KERNEL="${INSTALL_KERNEL:-1}"                   # 1=install the HWE generic kernel; 0=image already has it
PURGE_KERNEL="${PURGE_KERNEL:-}"                        # old kernel to purge, e.g. linux-image-6.8.0-106-generic; empty=do not purge
DNS_FALLBACK="${DNS_FALLBACK:-8.8.8.8 8.8.4.4 1.1.1.1}" # systemd-resolved fallback DNS; empty=skip this fix
NBD_RESET="${NBD_RESET:-1}"                             # reset the nbd module (max_part=16) before convert; 1=yes, 0=skip
# ====================

IN="${1:?usage: $0 <input-base.qcow2> <output-tapp.qcow2>}"
OUT="${2:?usage: $0 <input-base.qcow2> <output-tapp.qcow2>}"
[ -f "$IN" ] || { echo "input image not found: $IN" >&2; exit 1; }
[ -d "$CONFIG_DIR" ] || { echo "config dir not found: $CONFIG_DIR" >&2; exit 1; }
[ -f "$FDE_PACKAGE" ] || { echo "fde package not found: $FDE_PACKAGE" >&2; exit 1; }
export LIBGUESTFS_BACKEND=direct

IN_PLACE="${IN_PLACE:-0}"   # 1=operate directly on the input (modifies it, no copy); 0=copy first to protect the input
if [ "$IN_PLACE" = 1 ]; then
  WORK="$IN"
  echo "==> [0/4] IN_PLACE=1: operating directly on the input (will modify $WORK)"
else
  WORK="${IN%.qcow2}.prep-tmp.qcow2"
  echo "==> [0/4] copying input to work copy: $WORK"
  cp -f "$IN" "$WORK"
fi

# --- [1/4] kernel: the HWE generic kernel, on every platform ---
# One kernel for all targets. It used to be CLOUD-specific: GCP got linux-image-gcp because the
# noble GA generic kernel is 6.8, which lacks the TDX RTMR runtime-measurement interface (sysfs
# measurements/rtmrN:sha384 + EXTEND_RTMR ioctl, mainlined in 6.16) that every
# extend_runtime_measurement needs. Installing the HWE generic kernel (>=6.16) satisfies that on
# its own, so the split earned nothing but a second image and a second reference set.
#
# Verified on real GCP TDX hardware with 6.17.0-42-generic (same generation as the 6.17.0-1018-gcp
# it replaces): boots, gve/GVNIC brings up ens3, RTMR extend works (claim_config + start_app land
# in RTMR3), and the node's live measurement.uki equals the one extracted offline from the image.
# gve has been mainline since 5.3, so GCP networking needs no vendor kernel.
if [ "$INSTALL_KERNEL" = 1 ]; then
  echo "==> [1/4] installing newest COMPLETE generic kernel (TDX RTMR extend needs >=6.16)"
  # Not the bare HWE meta: it can race ahead of the archive (e.g. pulls a 7.0 image
  # whose linux-modules-extra-* is not published yet, which cryptpilot-convert needs
  # for zram). Pick the newest versioned generic kernel that HAS its modules-extra.
  vc_args=(-a "$WORK" --run-command '
    set -e
    apt-get update
    v=$(apt-cache pkgnames linux-modules-extra- \
        | grep -E "^linux-modules-extra-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$" \
        | sed "s/^linux-modules-extra-//" | sort -V | tail -1)
    [ -n "$v" ] || { echo "ERROR: no generic kernel with modules-extra found"; exit 1; }
    case "$v" in 6.[0-9].*|6.1[0-5].*|[1-5].*) echo "ERROR: newest complete kernel $v lacks TDX RTMR extend (>=6.16 needed)"; exit 1 ;; esac
    echo "installing kernel $v"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "linux-image-$v" "linux-modules-extra-$v"
  ')
  # Purge the GA 6.8 kernel: it lacks TDX RTMR extend, and (grub mode) would
  # linger as an alternate bootable menu entry. The kernel installed above
  # stays, satisfying convert's need for one *-generic kernel.
  vc_args+=(--run-command 'apt-get purge -y "linux-image-6.8.*" "linux-modules-6.8.*" "linux-headers-6.8*" 2>/dev/null || true; apt-get autoremove -y || true')
  [ -n "$PURGE_KERNEL" ] && vc_args+=(--run-command "apt-get autoremove --purge $PURGE_KERNEL -y || true")
  vc_args+=(--run-command 'update-grub')
  virt-customize "${vc_args[@]}"
else
  echo "==> [1/4] skipping kernel install (INSTALL_KERNEL=0)"
fi
echo "==> [fix A] point /boot/vmlinuz and initrd.img symlinks at the newest generic kernel"
virt-customize -a "$WORK" --run-command '
  set -e
  k=$(ls /boot/vmlinuz-*-generic 2>/dev/null | sort -V | tail -1 | sed "s#/boot/##")
  [ -n "$k" ] || { echo "ERROR: no generic kernel (vmlinuz-*-generic) in the image -- this image now boots one HWE generic kernel on every platform, so a base carrying only a vendor kernel needs INSTALL_KERNEL=1 to have one installed"; exit 1; }
  ln -sf "$k" /boot/vmlinuz
  ln -sf "initrd.img-${k#vmlinuz-}" /boot/initrd.img
  echo "vmlinuz -> $k"
'

# --- [1a/4] GPU confidential computing (ENABLE_GPU=1, opt-in) ---
# Same base image, same pipeline; GPU is one more stage rather than a second product.
# It has to run HERE -- after the kernel install above, before convert -- because the driver
# builds a kernel module and Stage A still had the base 6.8 GA kernel, which this image does
# not boot. With only the target kernel's headers present, DKMS builds against it.
#
# Driver: the OPEN kernel module, which confidential computing mode requires -- not optional.
#
# 580, the floor GCP's confidential-GPU guidance gives ("580 or higher"). That floor is real here
# rather than advisory: 575.57.08 does NOT build against this image's 6.17 kernel -- measured, the
# module fails on `implicit declaration of function 'dma_buf_attachment_is_dynamic'`, a symbol
# 6.17 took out of the public dma-buf headers and that NVIDIA's conftest does not probe for.
# Alibaba pins 550/570 because their platform runs a 5.10 kernel; ours must be >=6.16 for the TDX
# RTMR interface, so a newer driver is the matched pair and there is nothing to retreat to.
#
# Fabric Manager -- which multi-GPU needs for NVSwitch, and Protected PCIe with it -- comes from
# the UNVERSIONED package: NVIDIA drops the branch suffix on its newest line, so while
# nvidia-fabricmanager-575 exists, 580's counterpart is plain `nvidia-fabricmanager`. It must be
# version-pinned rather than just installed, because that package now resolves to 610/615 and
# Fabric Manager has to match the driver exactly. Pinning to the version the driver itself
# resolved to is the only pairing that stays correct as the repo moves.
#
# It is installed unconditionally and left DISABLED: only multi-GPU hosts need it, but installing
# it later would change the measurement and put every node on a new image, whereas enabling the
# service at runtime does not. So one image serves single- and multi-GPU hosts.
#
# Everything lands in the verity-sealed rootfs and the initrd, so a GPU image measures
# differently from a CPU-only one and carries its own reference values. That is expected.
if [ "${ENABLE_GPU:-0}" = 1 ]; then
  echo "==> [1a/4] ENABLE_GPU=1: NVIDIA open driver ${NVIDIA_DRIVER_BRANCH:-580} + container toolkit + CC mode"
  virt-customize -a "$WORK" --run-command "
    set -e
    export DEBIAN_FRONTEND=noninteractive
    k=\$(ls /boot/vmlinuz-*-generic | sort -V | tail -1 | sed 's#/boot/vmlinuz-##')
    echo \"building driver against kernel \$k\"
    apt-get update
    # DKMS needs the TARGET kernel's headers; only they are present, so it cannot pick another.
    apt-get install -y \"linux-headers-\$k\" dkms build-essential curl ca-certificates gnupg

    # NVIDIA CUDA repo (driver) + libnvidia-container repo (container toolkit)
    curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
    dpkg -i /tmp/cuda-keyring.deb && rm -f /tmp/cuda-keyring.deb
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      > /etc/apt/sources.list.d/nvidia-container-toolkit.list
    apt-get update

    apt-get install -y nvidia-driver-${NVIDIA_DRIVER_BRANCH:-580}-open nvidia-container-toolkit
    nvidia-ctk runtime configure --runtime=docker            # register the nvidia runtime with docker

    # Pin Fabric Manager to the version the driver actually resolved to (see header).
    drvver=\$(dpkg-query -W -f='\${Version}' nvidia-dkms-${NVIDIA_DRIVER_BRANCH:-580}-open | sed 's/-.*//')
    echo \"pinning Fabric Manager to the driver's own version: \$drvver\"
    apt-get install -y \"nvidia-fabricmanager=\$drvver-*\" \
      || { echo \"ERROR: no nvidia-fabricmanager matching driver \$drvver; multi-GPU needs an exact match\"; exit 1; }
    systemctl disable nvidia-fabricmanager.service 2>/dev/null || true

    # Confidential computing mode. nvidia-smi conf-compute -srs 1 has to run once the driver is
    # up on the real machine, so it hangs off nvidia-persistenced -- which CC also needs anyway,
    # since the CPU<->GPU SPDM session requires persistence mode.
    mkdir -p /etc/systemd/system/nvidia-persistenced.service.d
    printf '%s\n' '[Service]' 'ExecStartPost=-/usr/bin/nvidia-smi conf-compute -srs 1' \
      > /etc/systemd/system/nvidia-persistenced.service.d/10-cc-mode.conf
    systemctl enable nvidia-persistenced.service || true

    # Linux Kernel Crypto API, required to bring up that SPDM session (GCP's guidance).
    printf '%s\n' ecdsa_generic ecdh > /etc/modules-load.d/nvidia-cc-lkca.conf

    # The module must exist for the kernel this image boots, or none of the above matters.
    test -f \"/lib/modules/\$k/updates/dkms/nvidia.ko\" \
      || test -f \"/lib/modules/\$k/updates/dkms/nvidia.ko.zst\" \
      || { echo \"ERROR: nvidia.ko was not built for \$k -- driver ${NVIDIA_DRIVER_BRANCH:-580} may not support this kernel\"; exit 1; }
    echo \"nvidia.ko present for \$k\"
  "
fi

# --- [1b/4] boot-format prerequisites (BOOT_FORMAT-specific): UKI needs dracut + systemd-boot ---
if [ "$BOOT_FORMAT" = uki ]; then
  # convert --uki builds a Unified Kernel Image via dracut + systemd-boot. dracut-network: the
  # cryptpilot-fde-guest deb (installed during convert) depends on it; pre-install so the deb install
  # doesn't hit a missing-dep dpkg error mid-convert (convert auto-resolves it, but cleaner up front).
  echo "==> [1b/4] BOOT_FORMAT=uki: install dracut + systemd-boot-efi (UKI prerequisites)"
  virt-customize -a "$WORK" \
    --run-command 'apt-get update' \
    --install dracut,dracut-core,dracut-network,systemd-boot-efi
fi

if [ -n "$DNS_FALLBACK" ]; then
  echo "==> [fix C] DNS: FallbackDNS (virt-customize) + static /etc/resolv.conf (guestfish)"
  # FallbackDNS drop-in: this path is not touched by virt-customize teardown cleanup
  virt-customize -a "$WORK" --run-command "mkdir -p /etc/systemd/resolved.conf.d; printf '[Resolve]\nFallbackDNS=$DNS_FALLBACK\n' > /etc/systemd/resolved.conf.d/99-fallback-dns.conf"
  # /etc/resolv.conf must be written with guestfish: virt-customize drops a temporary resolv.conf for
  # networking and deletes its own copy during teardown; guestfish does not, so the file survives.
  # Must be written after all virt-customize runs; convert then backs it up/restores it, preserving it.
  _static="$(mktemp)"; for d in $DNS_FALLBACK; do echo "nameserver $d"; done > "$_static"
  guestfish --rw -a "$WORK" <<GF
run
mount /dev/sda1 /
rm-f /etc/resolv.conf
upload $_static /etc/resolv.conf
GF
  rm -f "$_static"
fi

if [ "$NBD_RESET" = 1 ]; then
  echo "==> [nbd] reset the nbd module (max_part=16) and clear stale devices"
  qemu-nbd -d /dev/nbd0 2>/dev/null || true
  qemu-nbd -d /dev/nbd1 2>/dev/null || true
  rmmod nbd 2>/dev/null || true
  modprobe nbd max_part=16
  partprobe /dev/nbd0 2>/dev/null || true
fi

echo "==> [2/4] cryptpilot-convert"
# Only fall back to /tmp when the inherited TMPDIR points at a path that does not exist inside the
# convert chroot (normal environments are left untouched, so the call matches a manual invocation)
case "${TMPDIR:-}" in
  ""|/tmp|/var/tmp) : ;;
  *) echo "   (TMPDIR=$TMPDIR is unusual; falling back to /tmp for convert)"; export TMPDIR=/tmp ;;
esac
CRYPTPILOT_CONVERT="${CRYPTPILOT_CONVERT:-cryptpilot-convert}"
# Boot format is its own dimension (BOOT_FORMAT): uki -> systemd-boot/UKI (--uki); grub -> shim/grub
# (convert #130 then syncs the regenerated grub.cfg to the ESP). Independent of cloud.
UKI_FLAG=""; [ "$BOOT_FORMAT" = uki ] && UKI_FLAG="--uki"
"$CRYPTPILOT_CONVERT" --in "$WORK" --out "$OUT" $UKI_FLAG \
  --config-dir "$CONFIG_DIR" $ROOTFS_MODE --package "$FDE_PACKAGE"

# NOTE: the old "[fix B] sync ESP grub.cfg + modules" step was removed — cryptpilot-convert now does
# it itself (openanolis/cryptpilot#130: syncs the regenerated grub.cfg + grub modules to the separate
# ESP grub.cfg on GCP-style images). Requires a convert that carries #130 (0.8.0 + the fork fix).

if [ "$IN_PLACE" != 1 ]; then
  echo "==> cleaning up work copy"
  rm -f "$WORK"
fi

echo ""
echo "[done] output: $OUT"
if [ "$CLOUD" = gcp ] && [ "$BOOT_FORMAT" = grub ]; then
  echo "  - verifying the kernel of the ESP default boot entry (GCP grub ESP layout /dev/sda15):"
  guestfish --ro -a "$OUT" <<'GF' 2>/dev/null | grep -m1 -E 'linux[[:space:]]+/vmlinuz' || true
run
mount /dev/sda15 /
cat /EFI/ubuntu/grub.cfg
GF
fi   # uki (no grub.cfg) / non-gcp ESP layout: skip this grub-specific verify — verify on a real boot.
echo "  tip: to compute reference values, run cryptpilot-fde show-reference-value --disk $OUT afterwards"
