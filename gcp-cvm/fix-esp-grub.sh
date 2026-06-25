#!/bin/bash
# fix-esp-grub.sh <image.qcow2>
#
# GCP Ubuntu images keep the full grub.cfg on the EFI partition at
# /EFI/ubuntu/grub.cfg, and grub reads only that at boot; meanwhile update-grub /
# cryptpilot-convert only update the boot partition's /boot/grub/grub.cfg.
# This script syncs the latest grub.cfg + grub modules from the boot partition to
# the EFI partition, fixing the post-kernel-swap boot crash ("vmlinuz not found" /
# "bli.mod not found").
#
# Usage: run this last (after virt-customize kernel swap + cryptpilot-convert).
# Touches only the ESP (sda15) and boot (sda16); never the verity rootfs. Idempotent.

set -euo pipefail

IMG="${1:?usage: $0 <image.qcow2>}"
[ -f "$IMG" ] || { echo "image not found: $IMG" >&2; exit 1; }
export LIBGUESTFS_BACKEND=direct

# Fixed GCP cloud-image layout: sda15=EFI(vfat), sda16=/boot(ext4).
# Mount sda16 at /, then mount sda15 at its own efi directory.
guestfish --rw -a "$IMG" <<'GF'
run
mount /dev/sda16 /
mount /dev/sda15 /efi
# assert: boot partition has grub.cfg and ESP has the ubuntu dir, otherwise the layout is wrong -> fail
is-file /grub/grub.cfg
is-dir  /efi/EFI/ubuntu
# back up the stale ESP config once (idempotent: drop the old backup first)
rm-f /efi/EFI/ubuntu/grub.cfg.stale
mv   /efi/EFI/ubuntu/grub.cfg /efi/EFI/ubuntu/grub.cfg.stale
# sync the latest grub.cfg + grub module directory to the ESP
cp /grub/grub.cfg /efi/EFI/ubuntu/grub.cfg
rm-rf /efi/EFI/ubuntu/x86_64-efi
cp-a  /grub/x86_64-efi /efi/EFI/ubuntu/x86_64-efi
GF

echo "[OK] synced ESP grub.cfg/modules: $IMG"
echo "---- kernel the ESP default entry now points to ----"
guestfish --ro -a "$IMG" <<'GF' 2>/dev/null | grep -E 'linux[[:space:]]+/vmlinuz' | head -1
run
mount /dev/sda15 /
cat /EFI/ubuntu/grub.cfg
GF
