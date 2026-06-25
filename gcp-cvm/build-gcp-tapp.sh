#!/bin/bash
# build-gcp-tapp.sh <ubuntu-24.04-base.qcow2> <output gcp-tapp.qcow2>
#
# 从一个“裸 Ubuntu 24.04 cloud 镜像”一键做出最终的 cryptpilot tapp 镜像。
# 两段：
#   [A] 装 base：tapp-server + service + /etc/tapp/config.toml + libtdx-attest(SGX repo)
#       + docker + systemd-resolved 兜底 DNS
#   [B] 复用 prepare-gcp-tapp.sh：装 gcp 内核 → 修 /boot/vmlinuz 软链 → convert → 同步 ESP
#
# 不修改输入镜像（全程副本）。需要本机/appliance 有网络（apt + 下载）。

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export LIBGUESTFS_BACKEND=direct
export DEBIAN_FRONTEND=noninteractive

# ===== 可调配置 =====
TAPP_SERVER_BIN="${TAPP_SERVER_BIN:-}"                              # 本机已有 tapp-server 路径；留空则从 URL 下载
TAPP_SERVER_URL="${TAPP_SERVER_URL:-https://github.com/0gfoundation/0g-tapp/releases/download/v0.1.0/tapp-server}"
OWNER_ADDRESS="${OWNER_ADDRESS:-0xea695C312CE119dE347425B29AFf85371c9d1837}"
KBS_URLS="${KBS_URLS:-\"http://8.222.225.233:9091\", \"http://47.245.117.71:9091\"}"
DNS_FALLBACK="${DNS_FALLBACK:-8.8.8.8 8.8.4.4 1.1.1.1}"
HARDEN="${HARDEN:-1}"                                   # 1=安全加固(purge Tier1/2+mask getty+换netplan); 0=不加固
# 传给 prepare-gcp-tapp.sh（convert 用）
export CONFIG_DIR="${CONFIG_DIR:-$HERE/config_dir}"
export FDE_PACKAGE="${FDE_PACKAGE:-$HERE/cryptpilot-fde_0.7.0_amd64.deb}"
export ROOTFS_MODE="${ROOTFS_MODE:---rootfs-no-encryption}"
export PURGE_KERNEL="${PURGE_KERNEL:-}"   # 注意：convert 需要镜像里至少保留一个 *-generic 内核，勿全删
export INSTALL_KERNEL=1
# ====================

IN="${1:?用法: $0 <ubuntu-24.04-base.qcow2> <output.qcow2>}"
OUT="${2:?用法: $0 <ubuntu-24.04-base.qcow2> <output.qcow2>}"
[ -f "$IN" ] || { echo "找不到输入镜像: $IN" >&2; exit 1; }
[ -f "$HERE/prepare-gcp-tapp.sh" ] || { echo "缺少 prepare-gcp-tapp.sh（应与本脚本同目录）" >&2; exit 1; }
[ -d "$CONFIG_DIR" ] || { echo "找不到 CONFIG_DIR: $CONFIG_DIR" >&2; exit 1; }
[ -f "$FDE_PACKAGE" ] || { echo "找不到 FDE_PACKAGE: $FDE_PACKAGE" >&2; exit 1; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ---- 取 tapp-server ----
if [ -n "$TAPP_SERVER_BIN" ]; then
  [ -f "$TAPP_SERVER_BIN" ] || { echo "TAPP_SERVER_BIN 不存在: $TAPP_SERVER_BIN" >&2; exit 1; }
  cp "$TAPP_SERVER_BIN" "$TMPD/tapp-server"
else
  echo "==> 下载 tapp-server: $TAPP_SERVER_URL"
  wget -q -O "$TMPD/tapp-server" "$TAPP_SERVER_URL" || { echo "下载失败，请改用 TAPP_SERVER_BIN=<本地路径>" >&2; exit 1; }
fi
echo "⚠️  注意：RTMR extend 是否可用取决于 tapp-server 是否基于 guest-components 8d71a3b4 构建（见文档 §8）。"
echo "    GitHub release tapp-server 若为旧版(5683fa5)，最终镜像仍会报 'Cannot extend runtime measurement'。"

# ---- 生成 service / config / dns 临时文件 ----
cat > "$TMPD/tapp-server.service" <<'EOF'
[Unit]
Description=TAPP gRPC Server - Trusted Application
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/tapp-server
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

Environment=PATH=/usr/local/bin:/usr/bin:/bin
# Environment=LD_LIBRARY_PATH=/usr/local/lib

NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

cat > "$TMPD/config.toml" <<EOF
[logging]
level = "info"
format = "pretty"
file_path = "/var/log/tapp/"

[server.permission]
enabled = true
owner_address = "$OWNER_ADDRESS"
initial_whitelist = []

[kbs]
node_urls = [$KBS_URLS]
EOF

printf '[Resolve]\nFallbackDNS=%s\n' "$DNS_FALLBACK" > "$TMPD/99-fallback-dns.conf"

# ---- 在 guest 内执行的 base 装配脚本 ----
cat > "$TMPD/provision-base.sh" <<'EOF'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl gnupg ca-certificates
install -d -m0755 /etc/apt/keyrings
# Intel SGX 源（libtdx-attest，tapp-server 运行时依赖）
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
  | gpg --dearmor -o /etc/apt/keyrings/intel-sgx.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
  > /etc/apt/sources.list.d/intel-sgx.list
# Docker 官方源
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y libtdx-attest docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
mkdir -p /var/log/tapp
systemctl enable docker tapp-server
EOF

# ===== 加固（HARDEN=1 时追加）：移除可绕过 tapp 改环境的软件（Tier1+Tier2，审计见文档 §11）=====
if [ "${HARDEN:-1}" = 1 ]; then
  echo "==> [加固] HARDEN=1：purge Tier1/2 + mask 控制台 getty + 换 MAC 无关 netplan"
  cat >> "$TMPD/provision-base.sh" <<'EOF'
PURGE_PKGS="openssh-server \
  google-guest-agent google-compute-engine google-compute-engine-oslogin google-osconfig-agent \
  cloud-init cloud-initramfs-copymods cloud-initramfs-dyn-netconf \
  snapd unattended-upgrades open-vm-tools google-cloud-ops-agent pollinate \
  landscape-common ubuntu-pro-client ubuntu-advantage-tools"
to_purge=""
for p in $PURGE_PKGS; do dpkg -s "$p" >/dev/null 2>&1 && to_purge="$to_purge $p" || true; done
[ -n "$to_purge" ] && { echo "purging: $to_purge"; apt-get purge -y $to_purge || true; }
apt-get autoremove --purge -y || true
rm -rf /snap /var/snap /var/lib/snapd
# 关闭控制台登录（GCP 串口 ttyS0 + 本地 tty1）
systemctl mask serial-getty@ttyS0.service getty@tty1.service || true
# 移除 cloud-init 后原按 MAC 匹配的 netplan 失效 → 换成 MAC 无关的 DHCP（否则新实例无网）
rm -f /etc/netplan/50-cloud-init.yaml /etc/netplan/90-default.yaml
cat > /etc/netplan/01-dhcp.yaml <<'NETEOF'
network:
  version: 2
  ethernets:
    alleth:
      match:
        name: "e*"
      dhcp4: true
      dhcp6: false
NETEOF
chmod 600 /etc/netplan/01-dhcp.yaml
EOF
else
  echo "==> [加固] HARDEN=0: dev variant, reinstall google-guest-agent to restore GCP SSH key injection"
  cat >> "$TMPD/provision-base.sh" <<'EOF'
# dev variant only: google-guest-agent (from Ubuntu universe) injects the instance
# SSH public key from metadata into ~ubuntu/.ssh/authorized_keys. It talks to the
# metadata server by the hostname metadata.google.internal by default; since we pin
# resolv.conf to public DNS (see fix C) that name will not resolve, so we also add a
# direct IP mapping (169.254.169.254) to /etc/hosts. Both are GCP back-door-class
# components and are intentionally NOT installed on the hardened variant.
apt-get install -y google-guest-agent
systemctl enable google-guest-agent.service || true
grep -q 'metadata.google.internal' /etc/hosts || \
  printf '169.254.169.254 metadata.google.internal metadata\n' >> /etc/hosts
EOF
fi
chmod +x "$TMPD/provision-base.sh"

# ---- 段 A：直接在输入镜像上装配 base（不复制，会修改 $IN）----
echo "==> [A] 在 $IN 上装配 base（app/docker/SGX/config/DNS）"
virt-customize -a "$IN" \
  --upload "$TMPD/tapp-server":/usr/local/bin/tapp-server \
  --chmod 0755:/usr/local/bin/tapp-server \
  --upload "$TMPD/tapp-server.service":/etc/systemd/system/tapp-server.service \
  --mkdir /etc/tapp \
  --upload "$TMPD/config.toml":/etc/tapp/config.toml \
  --mkdir /etc/systemd/resolved.conf.d \
  --upload "$TMPD/99-fallback-dns.conf":/etc/systemd/resolved.conf.d/99-fallback-dns.conf \
  --run "$TMPD/provision-base.sh"

# ---- 段 B：内核 + convert + ESP（IN_PLACE 直接用输入，复用已验证脚本）----
echo "==> [B] prepare-gcp-tapp.sh (IN_PLACE): 装 gcp 内核 → 修复A → convert → 修复B"
IN_PLACE=1 "$HERE/prepare-gcp-tapp.sh" "$IN" "$OUT"

echo ""
echo "[完成] 最终镜像: $OUT"
echo "（注意：$IN 已被就地修改，需要原始基础镜像请重新下载）"
