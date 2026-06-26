#!/bin/bash
# build-gcp-tapp.sh <ubuntu-24.04-base.qcow2> <output gcp-tapp.qcow2>
#
# One-command pipeline that turns a stock Ubuntu 24.04 cloud image into the final
# cryptpilot tapp image. Two stages:
#   [A] provision base: tapp-server + service + /etc/tapp/config.toml + libtdx-attest (SGX repo)
#       + docker + systemd-resolved fallback DNS
#   [B] reuse prepare-gcp-tapp.sh: install gcp kernel -> fix /boot/vmlinuz symlink -> convert -> sync ESP
#
# Requires network access on the host/appliance (apt + downloads).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export LIBGUESTFS_BACKEND=direct
export DEBIAN_FRONTEND=noninteractive

# ===== Tunables =====
TAPP_SERVER_BIN="${TAPP_SERVER_BIN:-}"                              # path to a local tapp-server binary; empty -> download from URL
TAPP_SERVER_URL="${TAPP_SERVER_URL:-https://github.com/0gfoundation/0g-tapp/releases/download/v0.1.0/tapp-server}"
OWNER_ADDRESS="${OWNER_ADDRESS:-}"   # REQUIRED: tapp-server owner address (0x...), written to config.toml [server.permission]
KBS_URLS="${KBS_URLS:-}"             # REQUIRED: KBS node URLs for [kbs] node_urls, comma-separated and quoted, e.g. KBS_URLS='"http://host1:9091", "http://host2:9091"'
DNS_FALLBACK="${DNS_FALLBACK:-8.8.8.8 8.8.4.4 1.1.1.1}"
HARDEN="${HARDEN:-1}"                                   # 1=hardened (purge Tier1/2 + mask getty + replace netplan); 0=dev
# Sysbox (issue #21): hostile-multi-tenant container isolation (sysbox-runc). Opt-in; default OFF.
# When ON: installs sysbox-ce, registers sysbox-runc as a dockerd runtime, and pins docker
# data-root to a persistent /data disk (the RAM rootfs overlay is ephemeral + RAM-capped, so
# docker/sysbox data MUST NOT live on it). The /data disk is provisioned per-instance at deploy
# time (attach a disk, format ext4, label "tapp-data"); docker will not start until it is mounted.
ENABLE_SYSBOX="${ENABLE_SYSBOX:-0}"
SYSBOX_VERSION="${SYSBOX_VERSION:-0.6.5}"
SYSBOX_DEB_URL="${SYSBOX_DEB_URL:-https://downloads.nestybox.com/sysbox/releases/v${SYSBOX_VERSION}/sysbox-ce_${SYSBOX_VERSION}-0.linux_amd64.deb}"
DATA_ROOT="${DATA_ROOT:-/data/docker}"                 # docker data-root when ENABLE_SYSBOX=1 (must be on the persistent /data disk)
# passed through to prepare-gcp-tapp.sh (used by convert)
export CONFIG_DIR="${CONFIG_DIR:-$HERE/config_dir}"
export FDE_PACKAGE="${FDE_PACKAGE:-$HERE/cryptpilot-fde_0.7.0_amd64.deb}"
export ROOTFS_MODE="${ROOTFS_MODE:---rootfs-no-encryption}"
export PURGE_KERNEL="${PURGE_KERNEL:-}"   # NOTE: convert needs at least one *-generic kernel left in the image; do not purge them all
export INSTALL_KERNEL=1
# ====================

IN="${1:?usage: $0 <ubuntu-24.04-base.qcow2> <output.qcow2>}"
OUT="${2:?usage: $0 <ubuntu-24.04-base.qcow2> <output.qcow2>}"
[ -f "$IN" ] || { echo "input image not found: $IN" >&2; exit 1; }
[ -n "$OWNER_ADDRESS" ] || { echo "OWNER_ADDRESS is required, e.g. OWNER_ADDRESS=0x... $0 ..." >&2; exit 1; }
[ -n "$KBS_URLS" ] || { echo "KBS_URLS is required, e.g. KBS_URLS='\"http://host1:9091\", \"http://host2:9091\"' $0 ..." >&2; exit 1; }
[ -f "$HERE/prepare-gcp-tapp.sh" ] || { echo "missing prepare-gcp-tapp.sh (must be in the same directory as this script)" >&2; exit 1; }
[ -d "$CONFIG_DIR" ] || { echo "CONFIG_DIR not found: $CONFIG_DIR" >&2; exit 1; }
[ -f "$FDE_PACKAGE" ] || { echo "FDE_PACKAGE not found: $FDE_PACKAGE" >&2; exit 1; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ---- obtain tapp-server ----
if [ -n "$TAPP_SERVER_BIN" ]; then
  [ -f "$TAPP_SERVER_BIN" ] || { echo "TAPP_SERVER_BIN does not exist: $TAPP_SERVER_BIN" >&2; exit 1; }
  cp "$TAPP_SERVER_BIN" "$TMPD/tapp-server"
else
  echo "==> downloading tapp-server: $TAPP_SERVER_URL"
  wget -q -O "$TMPD/tapp-server" "$TAPP_SERVER_URL" || { echo "download failed; use TAPP_SERVER_BIN=<local path> instead" >&2; exit 1; }
fi
echo "⚠️  NOTE: RTMR extend works only if tapp-server is built on guest-components 8d71a3b4 (see doc §8)."
echo "    An older GitHub-release tapp-server (5683fa5) will still report 'Cannot extend runtime measurement'."

# ---- generate temporary service / config / dns files ----
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

# ---- base provisioning script run inside the guest ----
cat > "$TMPD/provision-base.sh" <<'EOF'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl gnupg ca-certificates
install -d -m0755 /etc/apt/keyrings
# Intel SGX repo (libtdx-attest, a runtime dependency of tapp-server)
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
  | gpg --dearmor -o /etc/apt/keyrings/intel-sgx.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
  > /etc/apt/sources.list.d/intel-sgx.list
# Docker official repo
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y libtdx-attest docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
mkdir -p /var/log/tapp
systemctl enable docker tapp-server
EOF

# ===== Hardening (appended when HARDEN=1): remove software that can bypass tapp and mutate the environment (Tier1+Tier2, audit in doc §11) =====
if [ "${HARDEN:-1}" = 1 ]; then
  echo "==> [harden] HARDEN=1: purge Tier1/2 + mask console getty + replace netplan with a MAC-agnostic one"
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
# disable console login (GCP serial ttyS0 + local tty1)
systemctl mask serial-getty@ttyS0.service getty@tty1.service || true
# after removing cloud-init the original MAC-matched netplan breaks -> replace with a MAC-agnostic DHCP config (otherwise a new instance has no network)
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
  echo "==> [harden] HARDEN=0: dev variant, reinstall google-guest-agent to restore GCP SSH key injection"
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

# ===== Sysbox (issue #21, Phase 1: container isolation; opt-in) =====
if [ "$ENABLE_SYSBOX" = 1 ]; then
  echo "==> [sysbox] ENABLE_SYSBOX=1: install sysbox-ce $SYSBOX_VERSION, register sysbox-runc, pin docker data-root to $DATA_ROOT"
  # NOTE: heredoc is unquoted so $SYSBOX_DEB_URL / $DATA_ROOT are interpolated here (host side).
  cat >> "$TMPD/provision-base.sh" <<EOF
# --- Sysbox: hostile-multi-tenant container isolation (sysbox-runc, userns remap) ---
export DEBIAN_FRONTEND=noninteractive
apt-get install -y jq rsync fuse || true
wget -qO /tmp/sysbox-ce.deb "$SYSBOX_DEB_URL"
dpkg -i /tmp/sysbox-ce.deb || apt-get -f install -y
rm -f /tmp/sysbox-ce.deb
systemctl enable sysbox.service || true
# docker daemon.json: data-root on the persistent /data disk (the cryptpilot RAM rootfs overlay is
# ephemeral + RAM-capped, so docker/sysbox state MUST NOT live on it), plus sysbox-runc runtime.
# Written AFTER the sysbox deb so it wins over the deb's own daemon.json edits.
mkdir -p /etc/docker
printf '%s\n' '{' '  "data-root": "$DATA_ROOT",' '  "runtimes": { "sysbox-runc": { "path": "/usr/bin/sysbox-runc" } }' '}' > /etc/docker/daemon.json
# /data is a per-instance persistent disk; docker must wait for it and FAIL LOUD if absent
# (never silently fall back to the RAM root). Deploy step: attach a disk, mkfs.ext4 -L tapp-data.
mkdir -p /data
mkdir -p /etc/systemd/system/docker.service.d
printf '%s\n' '[Unit]' 'RequiresMountsFor=/data' > /etc/systemd/system/docker.service.d/10-data-mount.conf
grep -q 'LABEL=tapp-data' /etc/fstab || printf '%s\n' 'LABEL=tapp-data /data ext4 defaults 0 2' >> /etc/fstab
EOF
fi
chmod +x "$TMPD/provision-base.sh"

# ---- stage A: provision base directly on the input image (no copy, $IN is modified) ----
echo "==> [A] provisioning base on $IN (app/docker/SGX/config/DNS)"
virt-customize -a "$IN" \
  --upload "$TMPD/tapp-server":/usr/local/bin/tapp-server \
  --chmod 0755:/usr/local/bin/tapp-server \
  --upload "$TMPD/tapp-server.service":/etc/systemd/system/tapp-server.service \
  --mkdir /etc/tapp \
  --upload "$TMPD/config.toml":/etc/tapp/config.toml \
  --mkdir /etc/systemd/resolved.conf.d \
  --upload "$TMPD/99-fallback-dns.conf":/etc/systemd/resolved.conf.d/99-fallback-dns.conf \
  --run "$TMPD/provision-base.sh"

# ---- stage B: kernel + convert + ESP (IN_PLACE operates on the input, reusing the validated script) ----
echo "==> [B] prepare-gcp-tapp.sh (IN_PLACE): install gcp kernel -> fix A -> convert -> fix B"
IN_PLACE=1 "$HERE/prepare-gcp-tapp.sh" "$IN" "$OUT"

echo ""
echo "[done] final image: $OUT"
echo "(note: $IN was modified in place; re-download the original base image if you need it again)"
