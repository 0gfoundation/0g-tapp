#!/bin/bash
# prepare-gcp-tapp.sh <input-base.qcow2> <output-tapp.qcow2>
#
# Turn a GCP Ubuntu base image into a working cryptpilot tapp image.
# Chains four steps, two of which are the key fixes:
#   [kernel swap] install linux-image-gcp (optional, when INSTALL_KERNEL=1)
#   [fix A] point the /boot/vmlinuz symlink at the gcp kernel -- so convert builds the
#           cryptpilot-enabled initrd for the correct kernel
#           (otherwise: read-only rootfs / RTMR not extended / verity bypassed)
#   [convert] cryptpilot-convert (auto-sets TMPDIR=/tmp to avoid dracut failing in chroot)
#   [fix B] sync the boot-partition grub.cfg + modules to the ESP -- fixes the grub boot
#           crash (bli.mod / vmlinuz not found)
#
# By default does not modify the input image (works on a copy).

set -euo pipefail

# ===== Tunables =====
CONFIG_DIR="${CONFIG_DIR:-./config_dir}"
FDE_PACKAGE="${FDE_PACKAGE:-cryptpilot-fde_0.7.0_amd64.deb}"
ROOTFS_MODE="${ROOTFS_MODE:---rootfs-no-encryption}"   # or "--rootfs-passphrase <pass>"
INSTALL_KERNEL="${INSTALL_KERNEL:-1}"                   # 1=install gcp kernel; 0=image already has it
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

if [ "$INSTALL_KERNEL" = 1 ]; then
  echo "==> [1/4] installing gcp kernel (virt-customize)"
  vc_args=(-a "$WORK" --install linux-image-gcp,linux-modules-extra-gcp)
  [ -n "$PURGE_KERNEL" ] && vc_args+=(--run-command "apt-get autoremove --purge $PURGE_KERNEL -y || true")
  vc_args+=(--run-command 'update-grub')
  virt-customize "${vc_args[@]}"
else
  echo "==> [1/4] skipping kernel install (INSTALL_KERNEL=0)"
fi

echo "==> [fix A] point /boot/vmlinuz and initrd.img symlinks at the gcp kernel"
virt-customize -a "$WORK" --run-command '
  set -e
  k=$(ls /boot/vmlinuz-*-gcp 2>/dev/null | sort -V | tail -1 | sed "s#/boot/##")
  [ -n "$k" ] || { echo "ERROR: no gcp kernel (vmlinuz-*-gcp) in the image"; exit 1; }
  ln -sf "$k" /boot/vmlinuz
  ln -sf "initrd.img-${k#vmlinuz-}" /boot/initrd.img
  echo "vmlinuz -> $k"
'

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
cryptpilot-convert --in "$WORK" --out "$OUT" \
  --config-dir "$CONFIG_DIR" $ROOTFS_MODE --package "$FDE_PACKAGE"

echo "==> [fix B] sync ESP grub.cfg + modules (sda15<-sda16)"
guestfish --rw -a "$OUT" <<'GF'
run
mount /dev/sda16 /
mount /dev/sda15 /efi
is-file /grub/grub.cfg
is-dir  /efi/EFI/ubuntu
rm-f /efi/EFI/ubuntu/grub.cfg.stale
mv   /efi/EFI/ubuntu/grub.cfg /efi/EFI/ubuntu/grub.cfg.stale
cp   /grub/grub.cfg /efi/EFI/ubuntu/grub.cfg
rm-rf /efi/EFI/ubuntu/x86_64-efi
cp-a  /grub/x86_64-efi /efi/EFI/ubuntu/x86_64-efi
GF

if [ "$IN_PLACE" != 1 ]; then
  echo "==> cleaning up work copy"
  rm -f "$WORK"
fi

echo ""
echo "[done] output: $OUT"
echo "  - verifying the kernel of the ESP default boot entry:"
guestfish --ro -a "$OUT" <<'GF' 2>/dev/null | grep -m1 -E 'linux[[:space:]]+/vmlinuz' || true
run
mount /dev/sda15 /
cat /EFI/ubuntu/grub.cfg
GF
echo "  tip: to compute reference values, run cryptpilot-fde show-reference-value --disk $OUT afterwards"
