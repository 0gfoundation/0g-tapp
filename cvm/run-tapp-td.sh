#!/bin/bash
# Launch the tapp CVM image as a TDX Trust Domain on a bare-metal TDX host.
#
# TDX flags are taken verbatim from canonical/tdx's own launchers on this host
# (/opt/tdx/guest-tools/run_td and direct-boot/boot_direct.sh), not invented:
#   -object tdx-guest with quote-generation-socket vsock cid=2 port=4050  <- how the TD reaches QGS
#   -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off
#   -bios /usr/share/ovmf/OVMF.fd  (the TDVF)
#
# Differences from their examples, both deliberate:
#   * disk boot, not -kernel/-initrd direct boot: this image carries its own UEFI/UKI on its
#     ESP and cryptpilot assembles the rootfs in the initrd stage, so it must boot itself.
#   * a SECOND disk for /data. The image's tapp-data-provision.service formats and labels
#     "the single non-boot disk", and refuses to guess with 0 or >1 candidates -- so attach
#     exactly one, and never a seed ISO as a disk (a CD-ROM is fine, it shows up as sr0).
#
# No debug: td_attributes.debug must stay false or verify-app's policy rejects the quote.
set -euo pipefail

IMG="${IMG:-/home/ubuntu/tapp.qcow2}"
DATA="${DATA:-/home/ubuntu/tapp-data.qcow2}"
TDVF="${TDVF:-/usr/share/ovmf/OVMF.fd}"
MEM="${MEM:-64G}"          # / = ~4G read-only base + MEM (the rootfs overlay is RAM-backed zram)
CPUS="${CPUS:-16}"
SSH_PORT="${SSH_PORT:-10022}"   # host port -> guest 22
GRPC_PORT="${GRPC_PORT:-50051}" # host port -> guest 50051 (tapp-server)
LOG="${LOG:-/home/ubuntu/td-serial.log}"

for f in "$IMG" "$DATA" "$TDVF"; do
  [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

echo "==> launching TD: mem=$MEM cpus=$CPUS  ssh=:$SSH_PORT  grpc=:$GRPC_PORT"
echo "    serial -> $LOG"

exec qemu-system-x86_64 \
  -accel kvm \
  -m "$MEM" -smp "$CPUS" \
  -name tapp-td,process=tapp-td,debug-threads=on \
  -cpu host \
  -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type": "vsock", "cid":"2","port":"4050"}}' \
  -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off \
  -bios "$TDVF" \
  -nographic -nodefaults \
  -drive "file=$IMG,if=none,id=virtio-disk0" \
  -device virtio-blk-pci,drive=virtio-disk0 \
  -drive "file=$DATA,if=none,id=virtio-disk1" \
  -device virtio-blk-pci,drive=virtio-disk1 \
  -device virtio-net-pci,netdev=nic0 \
  -netdev "user,id=nic0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${GRPC_PORT}-:50051" \
  -serial "file:$LOG" \
  -pidfile /home/ubuntu/tapp-td.pid
