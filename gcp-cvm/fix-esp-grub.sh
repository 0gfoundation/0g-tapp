#!/bin/bash
# fix-esp-grub.sh <image.qcow2>
#
# GCP Ubuntu 镜像把完整 grub.cfg 放在 EFI 分区 /EFI/ubuntu/grub.cfg，grub 启动只读它；
# 而 update-grub / cryptpilot-convert 只更新 boot 分区的 /boot/grub/grub.cfg。
# 本脚本把 boot 分区上最新的 grub.cfg + grub 模块同步到 EFI 分区，
# 修复换内核后 "vmlinuz not found" / "bli.mod not found" 的启动崩溃。
#
# 用法: 放在流程最后(virt-customize 换内核 + cryptpilot-convert 之后)执行。
# 只读写 ESP(sda15) 和 boot(sda16)，不碰 verity rootfs。幂等，可重复跑。

set -euo pipefail

IMG="${1:?用法: $0 <image.qcow2>}"
[ -f "$IMG" ] || { echo "找不到镜像: $IMG" >&2; exit 1; }
export LIBGUESTFS_BACKEND=direct

# GCP 云镜像固定布局: sda15=EFI(vfat), sda16=/boot(ext4)。
# 把 sda16 挂在 /，再用它自带的 efi 目录挂 sda15。
guestfish --rw -a "$IMG" <<'GF'
run
mount /dev/sda16 /
mount /dev/sda15 /efi
# 断言: boot 分区有 grub.cfg，ESP 有 ubuntu 目录，否则布局不符直接报错
is-file /grub/grub.cfg
is-dir  /efi/EFI/ubuntu
# 备份一次过期的 ESP 配置(幂等: 先删旧备份)
rm-f /efi/EFI/ubuntu/grub.cfg.stale
mv   /efi/EFI/ubuntu/grub.cfg /efi/EFI/ubuntu/grub.cfg.stale
# 同步最新 grub.cfg + grub 模块目录到 ESP
cp /grub/grub.cfg /efi/EFI/ubuntu/grub.cfg
rm-rf /efi/EFI/ubuntu/x86_64-efi
cp-a  /grub/x86_64-efi /efi/EFI/ubuntu/x86_64-efi
GF

echo "[OK] 已同步 ESP grub.cfg/模块: $IMG"
echo "---- ESP 默认项现在指向的内核 ----"
guestfish --ro -a "$IMG" <<'GF' 2>/dev/null | grep -E 'linux[[:space:]]+/vmlinuz' | head -1
run
mount /dev/sda15 /
cat /EFI/ubuntu/grub.cfg
GF
