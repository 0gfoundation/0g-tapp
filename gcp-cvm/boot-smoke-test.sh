#!/bin/bash
# boot-smoke-test.sh <image.qcow2>
#
# Local boot smoke test for a converted GCP confidential image, WITHOUT needing a
# real GCP Confidential VM. Boots the image under QEMU/OVMF (UEFI) inside the
# qemux/qemu container and scans the serial console for the expected boot chain:
#
#   grub -> gcp kernel -> cryptpilot-fde (dm-verity + zram + dm-snapshot) ->
#   /sysroot mount -> switch-root -> multi-user / tapp-server.service
#
# This validates everything except the TDX-specific bits (RTMR extend, remote
# attestation), which require real hardware. It is meant as a fast pre-flight
# check before uploading an image to GCP, not a replacement for on-hardware tests.
#
# Uses hardware KVM when /dev/kvm is present, otherwise falls back to TCG software
# emulation (slower: expect several minutes to reach multi-user).
#
# Usage:
#   ./boot-smoke-test.sh out.qcow2
#   MAX=600 RAM_SIZE=4G CPU_CORES=4 ./boot-smoke-test.sh out.qcow2
#
# Exit code: 0 = boot confirmed, 1 = not confirmed / failure marker, 2 = setup error.

set -u

IMG="${1:?usage: $0 <image.qcow2>}"
[ -f "$IMG" ] || { echo "image not found: $IMG" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

MAX="${MAX:-600}"             # max seconds to wait for the boot to reach multi-user
RAM_SIZE="${RAM_SIZE:-4G}"
CPU_CORES="${CPU_CORES:-4}"
IMG_ABS="$(readlink -f "$IMG")"
NAME="boot-smoke-$$"
LOG="${LOG:-/tmp/boot-smoke.$$.serial.log}"

# Use KVM if available, otherwise TCG (KVM=N).
if [ -e /dev/kvm ]; then
    KVM_ENV=(-e KVM=Y --device=/dev/kvm)
    echo "==> /dev/kvm present: using hardware acceleration"
else
    KVM_ENV=(-e KVM=N)
    echo "==> no /dev/kvm: using TCG software emulation (slower)"
fi

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> booting $IMG under qemux/qemu (UEFI)…"
docker run -d --name "$NAME" \
    "${KVM_ENV[@]}" \
    -e BOOT_MODE=uefi -e RAM_SIZE="$RAM_SIZE" -e CPU_CORES="$CPU_CORES" -e DISK_FMT=qcow2 \
    --device=/dev/net/tun --cap-add NET_ADMIN \
    -v "$IMG_ABS":/boot.qcow2 \
    qemux/qemu >/dev/null 2>&1 || { echo "docker run failed" >&2; exit 2; }

PASS_RE='Welcome to Ubuntu|ubuntu login:|Reached target.*Multi-User|Started.*tapp-server'
FAIL_RE='Failed to boot both|entering emergency|dropped into an emergency|Kernel panic'

pass=0; t=0
: > "$LOG"
while [ "$t" -lt "$MAX" ]; do
    docker logs "$NAME" > "$LOG" 2>&1 || true
    if grep -qiE "$PASS_RE" "$LOG"; then pass=1; break; fi
    if grep -qiE "$FAIL_RE" "$LOG"; then echo "!! boot failure marker detected"; break; fi
    sleep 12; t=$((t + 12))
done

echo "==== serial markers (waited ${t}s) ===="
grep -niE 'cryptpilot-fde|device-mapper: verity|Setting up dm-verity|dm-snapshot device chain created|Mounted .*sysroot|switch.?root|Welcome to Ubuntu|ubuntu login:|Multi-User System|tapp-server|not found|Failed to boot|emergency|panic' "$LOG" | tail -45

echo "==== verdict ===="
if [ "$pass" -eq 1 ]; then
    echo "BOOT PASS (full serial log: $LOG)"
    exit 0
else
    echo "BOOT NOT CONFIRMED (full serial log: $LOG)"
    exit 1
fi
