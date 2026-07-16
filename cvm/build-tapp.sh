#!/bin/bash
# build-tapp.sh <ubuntu-24.04-base.qcow2> <output gcp-tapp.qcow2>
#
# One-command pipeline that turns a stock Ubuntu 24.04 cloud image into the final
# cryptpilot tapp image. Two stages:
#   [A] provision base: tapp-server + service + /etc/tapp/config.toml + libtdx-attest (SGX repo)
#       + docker + systemd-resolved fallback DNS
#   [B] reuse prepare-tapp.sh: install gcp kernel -> fix /boot/vmlinuz symlink -> convert -> sync ESP
#
# Requires network access on the host/appliance (apt + downloads).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export LIBGUESTFS_BACKEND=direct
export DEBIAN_FRONTEND=noninteractive

# ===== Tunables =====
TAPP_SERVER_BIN="${TAPP_SERVER_BIN:-}"                              # path to a local tapp-server binary; empty -> download from URL
TAPP_SERVER_URL="${TAPP_SERVER_URL:-https://github.com/0gfoundation/0g-tapp/releases/download/v0.1.0/tapp-server}"
OWNER_ADDRESS="${OWNER_ADDRESS:-}"   # OPTIONAL (legacy): bake an owner into config.toml [server.permission].
                                     # Empty (default) = build an OWNERLESS image: the tapp boots unclaimed and the
                                     # first valid signer of `tapp-cli claim-owner` becomes the owner (a measured
                                     # claim_owner runtime event). One image ⇒ one reference set for ALL owners.
KBS_URLS="${KBS_URLS:-}"             # REQUIRED: KBS node URLs for [kbs] node_urls, comma-separated and quoted, e.g. KBS_URLS='"http://host1:9091", "http://host2:9091"'
DNS_FALLBACK="${DNS_FALLBACK:-8.8.8.8 8.8.4.4 1.1.1.1}"
HARDEN="${HARDEN:-1}"                                   # 1=hardened (purge Tier1/2 + mask getty + replace netplan); 0=dev
# Docker version pin. Current docker-ce (28+/29+) breaks Sysbox: Docker 28+ emits the Linux time
# namespace in the OCI spec, which sysbox-runc rejects ("namespace ... does not exist"), and calls
# `sysbox-runc features` (unsupported) on startup. Nestybox officially supports Docker 20.10-27.x.
# Pin to the last 27.x; set DOCKER_VERSION="" to install the (unpinned) repo default instead.
DOCKER_VERSION="${DOCKER_VERSION:-5:27.5.1-1~ubuntu.24.04~noble}"
# Container storage is ALWAYS pinned off the RAM rootfs (rw_overlay="ram") onto the persistent /data
# disk -- this is independent of Sysbox. Two stores must be moved: docker's data-root (metadata)
# and containerd's root (image layers/snapshots; docker-ce defaults to the containerd image store).
# The /data disk is provisioned per-instance at deploy time (attach a disk, mkfs.ext4 -L tapp-data);
# docker + containerd wait for it and fail loud if it is absent (never write to the RAM root).
DATA_ROOT="${DATA_ROOT:-/data/docker}"                 # docker data-root (metadata/volumes/buildkit)
CONTAINERD_ROOT="${CONTAINERD_ROOT:-/data/containerd}" # containerd root (image layers + snapshots)
# Sysbox (issue #21): hostile-multi-tenant container isolation (sysbox-runc). Opt-in; default OFF.
# When ON: installs sysbox-ce and registers sysbox-runc as a dockerd runtime (storage pinning above
# happens regardless). Requires Docker <=27.x (see DOCKER_VERSION).
ENABLE_SYSBOX="${ENABLE_SYSBOX:-0}"
SYSBOX_VERSION="${SYSBOX_VERSION:-0.7.0}"
SYSBOX_DEB_URL="${SYSBOX_DEB_URL:-https://downloads.nestybox.com/sysbox/releases/v${SYSBOX_VERSION}/sysbox-ce_${SYSBOX_VERSION}-0.linux_amd64.deb}"
# Two independent build dimensions (each image = one of each):
#   CLOUD       gcp | ali  — kernel/guest/publish. gcp: linux-image-gcp + fix A + google-guest-agent +
#               publish-gcp-image.sh; ali: generic kernel + cloud-init(AliYun) + publish-ali-image.sh.
#   BOOT_FORMAT grub | uki — boot format (stage B convert). Defaults to grub for any cloud;
#               set uki explicitly. Determines --uki + UKI prereqs + the reference-value shape (grub 5 / uki 1).
# Both exported so prepare-*.sh (stage B) inherits them.
export CLOUD="${CLOUD:-gcp}"
export BOOT_FORMAT="${BOOT_FORMAT:-grub}"
# Boot-disk size of the produced image (the read-only verity rootfs sizes to this). Default 20G =
# the cached base. A larger value grows the working copy (qemu-img resize + growpart + resize2fs)
# up front, before the build; shrinking below the current size is unsupported (ignored).
DISK_SIZE="${DISK_SIZE:-20G}"
# passed through to prepare-tapp.sh (used by convert)
export CONFIG_DIR="${CONFIG_DIR:-$HERE/config_dir}"
export FDE_PACKAGE="${FDE_PACKAGE:-$HERE/cryptpilot-fde-guest_0.8.0_amd64.deb}"   # 0.8.0 in-image runtime (cryptpilot-fde split into -host/-guest at 0.8.0)
export ROOTFS_MODE="${ROOTFS_MODE:---rootfs-no-encryption}"
export PURGE_KERNEL="${PURGE_KERNEL:-}"   # NOTE: convert needs at least one *-generic kernel left in the image; do not purge them all
export INSTALL_KERNEL=1
# Stage C (opt-in): if set, publish $OUT to GCP as this image name after the build (raw -> tar.gz ->
# gsutil -> gcloud images create). Empty = build only. Needs gcloud/gsutil auth; see publish-gcp-image.sh
# (GCS_BUCKET / GCP_PROJECT / GUEST_OS_FEATURES are passed through to it).
PUBLISH_AS="${PUBLISH_AS:-}"
# ====================

IN="${1:?usage: $0 <ubuntu-24.04-base.qcow2> <output.qcow2>}"
OUT="${2:?usage: $0 <ubuntu-24.04-base.qcow2> <output.qcow2>}"
[ -f "$IN" ] || { echo "input image not found: $IN" >&2; exit 1; }
[ -n "$OWNER_ADDRESS" ] && echo "NOTE: baking OWNER_ADDRESS into the image (legacy per-owner reference values); leave it empty for an ownerless, claim-at-runtime image." >&2
[ -n "$KBS_URLS" ] || { echo "KBS_URLS is required, e.g. KBS_URLS='\"http://host1:9091\", \"http://host2:9091\"' $0 ..." >&2; exit 1; }
[ -f "$HERE/prepare-tapp.sh" ] || { echo "missing prepare-tapp.sh (must be in the same directory as this script)" >&2; exit 1; }
[ -d "$CONFIG_DIR" ] || { echo "CONFIG_DIR not found: $CONFIG_DIR" >&2; exit 1; }
[ -f "$FDE_PACKAGE" ] || { echo "FDE_PACKAGE not found: $FDE_PACKAGE" >&2; exit 1; }

# ---- resize the working image up front (before Stage A / convert) ----
# The final image's read-only verity rootfs is sized from the disk here, so grow the disk + rootfs
# partition (sda1) + filesystem now. Preserve partition numbering (growpart, NOT virt-resize --expand,
# which renumbers sda1->sda4 and breaks the sda1=rootfs / sda16=/boot assumptions). Only grows: a
# DISK_SIZE at or below the current size is a no-op (shrinking a populated fs is unsafe).
CUR_BYTES="$(qemu-img info --output=json "$IN" | python3 -c 'import sys,json; print(json.load(sys.stdin)["virtual-size"])')"
WANT_BYTES="$(numfmt --from=iec "$DISK_SIZE")"
if [ "$WANT_BYTES" -gt "$CUR_BYTES" ]; then
  echo "==> resize disk -> $DISK_SIZE (grow sda1 + fs; was $(numfmt --to=iec "$CUR_BYTES"))"
  qemu-img resize "$IN" "$DISK_SIZE"
  virt-customize -a "$IN" --run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1'
elif [ "$WANT_BYTES" -lt "$CUR_BYTES" ]; then
  echo "==> DISK_SIZE=$DISK_SIZE is below the current $(numfmt --to=iec "$CUR_BYTES"); shrinking unsupported — keeping current size" >&2
fi

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
# File logs live on the persistent /data disk (RAM rootfs would grow unbounded,
# issue #23) — same fail-loud policy as docker/containerd: no /data, no start.
RequiresMountsFor=/data

[Service]
Type=simple
User=root
Group=root
# Create /run/tapp (0755, cleaned on stop) so tapp-server can bind its unix_socket_path
# (/run/tapp/tapp.sock, see config.toml [server]) — app containers bind-mount this dir/socket.
RuntimeDirectory=tapp
RuntimeDirectoryMode=0755
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

# legacy baked owner: only emit the line when OWNER_ADDRESS was provided
OWNER_LINE=""
[ -n "$OWNER_ADDRESS" ] && OWNER_LINE="owner_address = \"$OWNER_ADDRESS\""

cat > "$TMPD/config.toml" <<EOF
[logging]
level = "info"
format = "pretty"
# On the persistent /data disk, NOT the RAM rootfs (rw_overlay="ram") — file
# logs on "/" consume RAM and are lost on reboot (issue #23). tapp-server keeps
# at most `max_log_files` daily files (default 7).
file_path = "/data/log/tapp/"

[server]
# Serve the gRPC service on this Unix domain socket in addition to TCP.
# App containers bind-mount this file and set their tapp socket path to it.
unix_socket_path = "/run/tapp/tapp.sock"

[server.permission]
enabled = true
# owner: unset ⇒ boots UNCLAIMED; first valid `tapp-cli claim-owner` signer
# becomes the owner (measured claim_owner runtime event). A baked owner
# (legacy) re-introduces per-owner reference values.
$OWNER_LINE

[kbs]
node_urls = [$KBS_URLS]
EOF

printf '[Resolve]\nFallbackDNS=%s\n' "$DNS_FALLBACK" > "$TMPD/99-fallback-dns.conf"

# ---- base provisioning script run inside the guest ----
# preamble: interpolate host-side tunables into the guest script (unquoted heredoc)
cat > "$TMPD/provision-base.sh" <<EOF
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
DOCKER_VERSION="$DOCKER_VERSION"
DATA_ROOT="$DATA_ROOT"
CONTAINERD_ROOT="$CONTAINERD_ROOT"
EOF
# main body (quoted heredoc: no host-side interpolation; uses the vars set above)
cat >> "$TMPD/provision-base.sh" <<'EOF'
apt-get update
apt-get install -y curl gnupg ca-certificates
install -d -m0755 /etc/apt/keyrings
# Intel SGX repo (libtdx-attest, a runtime dependency of tapp-server)
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
  | gpg --batch --no-tty --dearmor -o /etc/apt/keyrings/intel-sgx.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
  > /etc/apt/sources.list.d/intel-sgx.list
# Docker official repo
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --batch --no-tty --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
# Pin Docker to a Sysbox-compatible release (see DOCKER_VERSION note in the caller). Empty
# DOCKER_VERSION -> install the unpinned repo default.
if [ -n "${DOCKER_VERSION:-}" ]; then
  DOCKER_PKGS="docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION containerd.io docker-buildx-plugin docker-compose-plugin"
else
  DOCKER_PKGS="docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
fi
apt-get install -y libtdx-attest $DOCKER_PKGS
mkdir -p /var/log/tapp
systemctl enable docker tapp-server

# br_netfilter: container bridge networking with iptables -- and Docker 28's icc=false bridges (used
# by the 0g-sandbox runner) -- hard-require /proc/sys/net/bridge/bridge-nf-call-iptables, which only
# exists once br_netfilter is loaded. This minimal image does not autoload it, so a fresh CVM would
# crash the runner ("bridge-nf-call-iptables: no such file"). Persist it so every boot has it.
echo br_netfilter > /etc/modules-load.d/br_netfilter.conf

# ---- pin container storage OFF the ephemeral RAM rootfs (rw_overlay="ram") -- UNCONDITIONAL ----
# The cryptpilot writable rootfs overlay is RAM-backed and RAM-capped, so container state MUST NOT
# accumulate on "/". Independent of Sysbox. Two distinct stores must both move to the /data disk:
#   - docker's data-root : metadata, volumes, buildkit                              -> $DATA_ROOT
#   - containerd's root  : image layers + snapshots (docker-ce defaults to the      -> $CONTAINERD_ROOT
#                          containerd image store, so layers live here, NOT data-root)
# docker + containerd must wait for /data and FAIL LOUD if absent (never write to the RAM root).
mkdir -p /data /etc/docker /etc/containerd
printf '%s\n' '{' "  \"data-root\": \"$DATA_ROOT\"" '}' > /etc/docker/daemon.json
containerd config default > /etc/containerd/config.toml
sed -i "s|^root = .*|root = \"$CONTAINERD_ROOT\"|" /etc/containerd/config.toml
mkdir -p /etc/systemd/system/docker.service.d /etc/systemd/system/containerd.service.d
printf '%s\n' '[Unit]' 'RequiresMountsFor=/data' > /etc/systemd/system/docker.service.d/10-data-mount.conf
printf '%s\n' '[Unit]' 'RequiresMountsFor=/data' > /etc/systemd/system/containerd.service.d/10-data-mount.conf
# fstab: nofail so a missing/blank /data disk NEVER blocks boot (a non-nofail mount failure drops the
# whole system into emergency mode -> no network/SSH). With nofail only docker/containerd fail loud
# (RequiresMountsFor). x-systemd.requires pulls the provisioner first. device-timeout must comfortably
# exceed the provisioner's first-boot mkfs time: on a blank disk the by-label device only appears AFTER
# tapp-data-provision formats it, and the .device wait (which starts early in boot) must not expire
# before then, or data.mount fails on first boot. 60s >> the few seconds mkfs needs; it only ever
# delays boot in the (misconfigured) no-data-disk case, where nofail then lets boot proceed anyway.
grep -q 'LABEL=tapp-data' /etc/fstab || printf '%s\n' 'LABEL=tapp-data /data ext4 defaults,nofail,x-systemd.device-timeout=60s,x-systemd.requires=tapp-data-provision.service 0 2' >> /etc/fstab

# Auto-provision /data on first boot with NO SSH. Find the single non-boot whole disk and:
#   - blank (no filesystem signature)      -> mkfs.ext4 -L tapp-data     (fresh node)
#   - already ext4 (e.g. a migrated disk)  -> e2label tapp-data          (adopt, NEVER reformat)
# SAFE: only real disks (sd*/nvme*/vd*), never the boot disk, never a partitioned disk; with zero or
# more-than-one candidates it refuses to guess; an existing fs is adopted (labelled), never wiped.
# So attaching ANY single data disk -- brand-new or an old one carrying data -- just works, no SSH,
# no manual mkfs/label. A disk already labelled tapp-data short-circuits at the top. Idempotent.
cat > /usr/local/sbin/tapp-data-provision.sh <<'PROVSH'
#!/bin/bash
set -u
udevadm settle 2>/dev/null || true
# already have a tapp-data fs (labelled on an earlier boot, or operator-provided)? done.
blkid -L tapp-data >/dev/null 2>&1 && exit 0
# the boot disk carries the ESP (UEFI label) -- never touch it
esp="$(blkid -L UEFI 2>/dev/null)" || true
bootdisk=""
[ -n "${esp:-}" ] && bootdisk="$(lsblk -no pkname "$esp" 2>/dev/null | head -1)"
# collect candidate non-boot whole disks (no partitions)
cands=()
while read -r name type; do
  [ "$type" = disk ] || continue
  case "$name" in sd*|nvme*|vd*) ;; *) continue ;; esac                            # real disks only (skip zram/loop/dm/sr)
  [ "$name" = "$bootdisk" ] && continue                                            # never the boot disk
  [ -n "$(lsblk -rno NAME "/dev/$name" 2>/dev/null | tail -n +2)" ] && continue    # skip partitioned disks
  cands+=("/dev/$name")
done < <(lsblk -dno NAME,TYPE 2>/dev/null)
if [ "${#cands[@]}" -eq 0 ]; then
  echo "tapp-data-provision: no candidate data disk; /data stays unmounted (docker fails loud)" >&2; exit 0
elif [ "${#cands[@]}" -gt 1 ]; then
  echo "tapp-data-provision: multiple candidate disks (${cands[*]}); refusing to guess" >&2; exit 0
fi
dev="${cands[0]}"
fstype="$(blkid -p -s TYPE -o value "$dev" 2>/dev/null || true)"
if [ -z "$fstype" ]; then
  mkfs.ext4 -q -F -L tapp-data "$dev"
  echo "tapp-data-provision: formatted blank $dev as LABEL=tapp-data"
elif [ "$fstype" = ext4 ]; then
  e2label "$dev" tapp-data                                                         # adopt existing data, no reformat
  echo "tapp-data-provision: adopted existing ext4 $dev -> LABEL=tapp-data (data preserved)"
else
  echo "tapp-data-provision: $dev has unexpected fs '$fstype'; not touching it" >&2; exit 0
fi
PROVSH
chmod 0755 /usr/local/sbin/tapp-data-provision.sh
cat > /etc/systemd/system/tapp-data-provision.service <<'PROVUNIT'
[Unit]
Description=Auto-provision /data (format a blank data disk, or adopt an existing one, as tapp-data)
After=systemd-udev-settle.service
Wants=systemd-udev-settle.service
Before=data.mount

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/tapp-data-provision.sh
PROVUNIT

# Auto-grow /data to fill its disk on boot. A hardened image has no SSH and no cloud-init/growpart,
# so an oversized persistent disk would otherwise strip nothing back -- the extra space is wasted
# forever. This oneshot resizes the /data ext4 online to consume the whole device (idempotent;
# no-op once full), so operators can attach an arbitrarily large /data disk and it is fully used.
# NOTE: the BOOT disk is NOT grown -- the rootfs is verity + RAM overlay, so extra boot-disk space
# is unusable by design; size the boot disk ~= the image and put capacity on the /data disk.
cat > /usr/local/sbin/tapp-data-grow.sh <<'GROWSH'
#!/bin/bash
# grow the ext4 fs mounted at /data to fill its backing device (online resize; idempotent)
set -u
dev="$(findmnt -no SOURCE /data 2>/dev/null)" || exit 0
[ -n "$dev" ] || exit 0
dev="$(readlink -f "$dev")"
# if /data lives on a partition (not a whole disk), grow the partition first -- best-effort,
# needs growpart (cloud-guest-utils), which the hardened image does not ship; whole-disk ext4
# (the documented deploy: mkfs.ext4 -L tapp-data on the raw disk) needs no growpart.
base=""; partnum=""
[[ "$dev" =~ ^(/dev/nvme[0-9]+n[0-9]+)p([0-9]+)$ ]] && { base="${BASH_REMATCH[1]}"; partnum="${BASH_REMATCH[2]}"; }
[[ "$dev" =~ ^(/dev/[sv]d[a-z]+)([0-9]+)$ ]]        && { base="${BASH_REMATCH[1]}"; partnum="${BASH_REMATCH[2]}"; }
if [ -n "$base" ]; then
  if command -v growpart >/dev/null 2>&1; then growpart "$base" "$partnum" || true; partprobe "$base" 2>/dev/null || true
  else echo "tapp-data-grow: $dev is a partition but growpart is unavailable; only the filesystem will be resized" >&2; fi
fi
resize2fs "$dev" || true
GROWSH
chmod 0755 /usr/local/sbin/tapp-data-grow.sh
cat > /etc/systemd/system/tapp-data-grow.service <<'GROWUNIT'
[Unit]
Description=Grow the /data filesystem to fill its disk (no-SSH auto-expand)
After=data.mount
Requires=data.mount
Before=docker.service containerd.service
ConditionPathIsMountPoint=/data

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/tapp-data-grow.sh

[Install]
WantedBy=multi-user.target
GROWUNIT
systemctl enable tapp-data-grow.service || true
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
elif [ "$CLOUD" = gcp ]; then
  echo "==> [harden] HARDEN=0 gcp: reinstall google-guest-agent to restore GCP SSH key injection"
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
else
  # ali (or other) dev variant: the dev build does NOT purge cloud-init (only HARDEN=1 does), and on
  # Alibaba Cloud cloud-init injects the instance SSH key + configures networking from the Ali metadata
  # service (100.100.100.200). So no google-guest-agent (that is GCP-only) — rely on cloud-init, and
  # PIN its datasource to AliYun: Alibaba recommends pinning rather than relying on ds-identify picking
  # AliYun out of ~30 candidate datasources, so key/network injection is reliable.
  echo "==> [harden] HARDEN=0 $CLOUD: pin cloud-init datasource to AliYun for SSH/network injection (no google-guest-agent)"
  cat >> "$TMPD/provision-base.sh" <<'EOF'
mkdir -p /etc/cloud/cloud.cfg.d
printf 'datasource_list: [ AliYun ]\n' > /etc/cloud/cloud.cfg.d/99-aliyun-ds.cfg
EOF
fi

# ===== Sysbox (issue #21, Phase 1: container isolation; opt-in) =====
if [ "$ENABLE_SYSBOX" = 1 ]; then
  echo "==> [sysbox] ENABLE_SYSBOX=1: install sysbox-ce $SYSBOX_VERSION, register sysbox-runc runtime"
  # NOTE: heredoc is unquoted so $SYSBOX_DEB_URL is interpolated here (host side).
  cat >> "$TMPD/provision-base.sh" <<EOF
# --- Sysbox: hostile-multi-tenant container isolation (sysbox-runc, userns remap) ---
# Only the runtime registration is gated behind ENABLE_SYSBOX; the /data storage pinning above is
# unconditional. Requires Docker <=27.x (pinned above) -- sysbox-runc rejects the Linux time
# namespace that Docker 28+/29+ emits in the OCI spec.
export DEBIAN_FRONTEND=noninteractive
# fuse3 (not fuse/fuse2): sysbox-fs 0.7.0 uses libfuse3 and needs `fusermount3` to mount its
# per-container FUSE fs, else container launch fails with "fusermount3: not found / FuseServer InitWait".
apt-get install -y jq rsync fuse3 || true
wget -qO /tmp/sysbox-ce.deb "$SYSBOX_DEB_URL"
dpkg -i /tmp/sysbox-ce.deb || apt-get -f install -y
rm -f /tmp/sysbox-ce.deb
systemctl enable sysbox.service || true
# Keep sysbox's data store off the RAM rootfs: it holds per-container state AND inner-container
# images (docker-in-sysbox), which would otherwise pile onto "/". Relocate sysbox-mgr --data-root
# to /data via a drop-in that preserves the vendor ExecStart args, and make it wait for /data too.
sbx_unit="\$(ls /lib/systemd/system/sysbox-mgr.service /usr/lib/systemd/system/sysbox-mgr.service 2>/dev/null | head -1)"
if [ -n "\$sbx_unit" ]; then
  mkdir -p /data/sysbox /etc/systemd/system/sysbox-mgr.service.d
  sbx_exec="\$(sed -n 's/^ExecStart=//p' "\$sbx_unit" | head -1)"
  printf '%s\n' '[Unit]' 'RequiresMountsFor=/data' '[Service]' 'ExecStart=' "ExecStart=\$sbx_exec --data-root /data/sysbox" \
    > /etc/systemd/system/sysbox-mgr.service.d/10-data-root.conf
fi
# Merge the sysbox-runc runtime into the existing daemon.json (which already pins data-root),
# preserving it. Written AFTER the sysbox deb so it wins over the deb's own daemon.json edits.
tmp_dj="\$(mktemp)"
jq '.runtimes."sysbox-runc" = {"path": "/usr/bin/sysbox-runc"}' /etc/docker/daemon.json > "\$tmp_dj" && mv "\$tmp_dj" /etc/docker/daemon.json
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
echo "==> [B] prepare-tapp.sh (IN_PLACE): install gcp kernel -> fix A -> convert -> fix B"
IN_PLACE=1 "$HERE/prepare-tapp.sh" "$IN" "$OUT"

echo ""
echo "[done] final image: $OUT"
echo "(note: $IN was modified in place; re-download the original base image if you need it again)"

# ---- stage C (opt-in): publish $OUT as image $PUBLISH_AS on the target cloud ----
if [ -n "$PUBLISH_AS" ]; then
  case "$CLOUD" in
    gcp) PUBLISHER="$HERE/publish-gcp-image.sh" ;;
    ali) PUBLISHER="$HERE/publish-ali-image.sh" ;;
    *)   echo "unknown CLOUD=$CLOUD (expected gcp|ali)" >&2; exit 1 ;;
  esac
  [ -x "$PUBLISHER" ] || { echo "PUBLISH_AS set but $(basename "$PUBLISHER") not found/executable in $HERE" >&2; exit 1; }
  echo "==> [C] $(basename "$PUBLISHER"): $OUT -> $CLOUD image '$PUBLISH_AS'"
  "$PUBLISHER" "$OUT" "$PUBLISH_AS"
fi
