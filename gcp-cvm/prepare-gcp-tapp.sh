#!/bin/bash
# prepare-gcp-tapp.sh <input-base.qcow2> <output-tapp.qcow2>
#
# 一键把 GCP Ubuntu base 镜像做成可用的 cryptpilot tapp 镜像。
# 串起三件事，其中两处是关键修复：
#   [换内核] 装 linux-image-gcp（可选，INSTALL_KERNEL=1 时）
#   [修复 A] 把 /boot/vmlinuz 软链指向 gcp 内核  —— 让 convert 给正确内核建带 cryptpilot 的 initrd
#            （否则 rootfs 只读 / RTMR 不 extend / verity 被绕过）
#   [convert] cryptpilot-convert（自动加 TMPDIR=/tmp，避免 chroot 内 dracut 失败）
#   [修复 B] 把 boot 分区 grub.cfg + 模块同步到 ESP  —— 修 grub 启动崩溃(bli.mod/vmlinuz not found)
#
# 不修改输入镜像（全程在副本上操作）。

set -euo pipefail

# ===== 可按需调整的配置 =====
CONFIG_DIR="${CONFIG_DIR:-./config_dir}"
FDE_PACKAGE="${FDE_PACKAGE:-cryptpilot-fde_0.7.0_amd64.deb}"
ROOTFS_MODE="${ROOTFS_MODE:---rootfs-no-encryption}"   # 或 "--rootfs-passphrase <pass>"
INSTALL_KERNEL="${INSTALL_KERNEL:-1}"                   # 1=装 gcp 内核; 0=镜像已装好
PURGE_KERNEL="${PURGE_KERNEL:-}"                        # 要 purge 的旧内核，如 linux-image-6.8.0-106-generic；留空则不 purge
DNS_FALLBACK="${DNS_FALLBACK:-8.8.8.8 8.8.4.4 1.1.1.1}" # systemd-resolved 兜底 DNS；留空则跳过此修复
NBD_RESET="${NBD_RESET:-1}"                             # convert 前重置 nbd 模块(max_part=16)；1=做, 0=跳过
# ============================

IN="${1:?用法: $0 <input-base.qcow2> <output-tapp.qcow2>}"
OUT="${2:?用法: $0 <input-base.qcow2> <output-tapp.qcow2>}"
[ -f "$IN" ] || { echo "找不到输入镜像: $IN" >&2; exit 1; }
[ -d "$CONFIG_DIR" ] || { echo "找不到 config 目录: $CONFIG_DIR" >&2; exit 1; }
[ -f "$FDE_PACKAGE" ] || { echo "找不到 fde 包: $FDE_PACKAGE" >&2; exit 1; }
export LIBGUESTFS_BACKEND=direct

IN_PLACE="${IN_PLACE:-0}"   # 1=直接在输入镜像上操作(会修改输入,不复制); 0=复制副本保护输入
if [ "$IN_PLACE" = 1 ]; then
  WORK="$IN"
  echo "==> [0/4] IN_PLACE=1：直接在输入上操作(将修改 $WORK)"
else
  WORK="${IN%.qcow2}.prep-tmp.qcow2"
  echo "==> [0/4] 复制输入到工作副本: $WORK"
  cp -f "$IN" "$WORK"
fi

if [ "$INSTALL_KERNEL" = 1 ]; then
  echo "==> [1/4] 安装 gcp 内核 (virt-customize)"
  vc_args=(-a "$WORK" --install linux-image-gcp,linux-modules-extra-gcp)
  [ -n "$PURGE_KERNEL" ] && vc_args+=(--run-command "apt-get autoremove --purge $PURGE_KERNEL -y || true")
  vc_args+=(--run-command 'update-grub')
  virt-customize "${vc_args[@]}"
else
  echo "==> [1/4] 跳过内核安装 (INSTALL_KERNEL=0)"
fi

echo "==> [修复A] 把 /boot/vmlinuz、initrd.img 软链指向 gcp 内核"
virt-customize -a "$WORK" --run-command '
  set -e
  k=$(ls /boot/vmlinuz-*-gcp 2>/dev/null | sort -V | tail -1 | sed "s#/boot/##")
  [ -n "$k" ] || { echo "ERROR: 镜像里没有 gcp 内核 (vmlinuz-*-gcp)"; exit 1; }
  ln -sf "$k" /boot/vmlinuz
  ln -sf "initrd.img-${k#vmlinuz-}" /boot/initrd.img
  echo "vmlinuz -> $k"
'

if [ -n "$DNS_FALLBACK" ]; then
  echo "==> [修复C] DNS：FallbackDNS(virt-customize) + 静态 /etc/resolv.conf(guestfish)"
  # FallbackDNS drop-in：此路径不受 virt-customize 收尾清理影响
  virt-customize -a "$WORK" --run-command "mkdir -p /etc/systemd/resolved.conf.d; printf '[Resolve]\nFallbackDNS=$DNS_FALLBACK\n' > /etc/systemd/resolved.conf.d/99-fallback-dns.conf"
  # /etc/resolv.conf 必须用 guestfish 写：virt-customize 为联网临时放 resolv.conf、收尾会删掉它写的那份；
  # guestfish 不做这套，故能留住。须在所有 virt-customize 之后写；convert 随后备份/恢复，从而保留。
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
  echo "==> [nbd] 重置 nbd 模块 (max_part=16)，清理残留设备"
  qemu-nbd -d /dev/nbd0 2>/dev/null || true
  qemu-nbd -d /dev/nbd1 2>/dev/null || true
  rmmod nbd 2>/dev/null || true
  modprobe nbd max_part=16
  partprobe /dev/nbd0 2>/dev/null || true
fi

echo "==> [2/4] cryptpilot-convert"
# 仅当继承的 TMPDIR 指向 convert chroot 内不存在的路径时才兜底为 /tmp（正常环境不动，调用与手动一致）
case "${TMPDIR:-}" in
  ""|/tmp|/var/tmp) : ;;
  *) echo "   (TMPDIR=$TMPDIR 非常规，convert 兜底为 /tmp)"; export TMPDIR=/tmp ;;
esac
cryptpilot-convert --in "$WORK" --out "$OUT" \
  --config-dir "$CONFIG_DIR" $ROOTFS_MODE --package "$FDE_PACKAGE"

echo "==> [修复B] 同步 ESP grub.cfg + 模块 (sda15<-sda16)"
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
  echo "==> 清理工作副本"
  rm -f "$WORK"
fi

echo ""
echo "[完成] 产物: $OUT"
echo "  - 校验 ESP 默认启动项内核:"
guestfish --ro -a "$OUT" <<'GF' 2>/dev/null | grep -m1 -E 'linux[[:space:]]+/vmlinuz' || true
run
mount /dev/sda15 /
cat /EFI/ubuntu/grub.cfg
GF
echo "  提示: 若要算参考值，请在此之后执行 cryptpilot-fde show-reference-value --disk $OUT"
