#!/usr/bin/env bash
# setup-toolchain.sh [work-dir]
#
# Install the cryptpilot 0.8.0 toolchain + our unmerged fixes (#128 + #130) on the (al8) build host.
# Run once per runner (or when CRYPTPILOT_REF bumps). Idempotent-ish. Requires: al8, root, dnf, git,
# cargo/rust, cryptsetup-devel, gh (authenticated).
#
# Why 0.8.0 + a fork build (see gcp-cvm/cryptpilot-gcp-boot-fix.md §12/§14):
#   - #130 (fork) teaches cryptpilot-convert to handle GCP-style images (separate ESP grub.cfg +
#     vendor kernels) itself, so the build no longer needs the "keep a -generic kernel" + fix-B
#     ESP-sync workarounds.
#   - #128 (fork) makes cryptpilot-fde-host show-reference-value fall back to the default grub.cfg
#     menuentry on a never-booted image (empty grubenv).
#   Both are OPEN upstream PRs on the 0.8.0 base, so they are NOT in the released v0.8.0 RPMs; we
#   install the released 0.8.0 for the base/runtime/dracut, then overlay convert + fde-host built
#   from the fork commit that carries both fixes.
#
# Prints the 0.8.0 guest deb path (for FDE_PACKAGE / build-gcp-tapp.sh --package) on the last line.
set -euo pipefail

REL="${CRYPTPILOT_RELEASE:-v0.8.0}"
REPO="${CRYPTPILOT_REPO_URL:-https://github.com/0gfoundation/cryptpilot.git}"
# 0.8.0 + #128 + #130 (fork branch feat/0g-gcp-cvm). Bump deliberately; do not track a moving branch.
REF="${CRYPTPILOT_REF:-57d751259211c0b72fe22c855d95786865c7d84c}"
WORK="${1:-$HOME/.cache/cvm-ci}"; SRC="$WORK/cryptpilot-src"; ART="$WORK/artifacts"
GH="${GH:-gh}"
GUEST_DEB="cryptpilot-fde-guest_0.8.0_amd64.deb"
mkdir -p "$ART"

echo "==> [1/3] fetch + install released cryptpilot $REL RPMs (crypt/verity/fde-host) + guest deb" >&2
for a in cryptpilot-crypt-0.8.0-1.al8.x86_64.rpm cryptpilot-verity-0.8.0-1.al8.x86_64.rpm \
         cryptpilot-fde-host-0.8.0-1.al8.x86_64.rpm "$GUEST_DEB"; do
  [ -f "$ART/$a" ] || "$GH" release download "$REL" --repo openanolis/cryptpilot -p "$a" -D "$ART" >&2
done
dnf install -y --allowerasing "$ART"/cryptpilot-crypt-0.8.0*.rpm "$ART"/cryptpilot-verity-0.8.0*.rpm \
  "$ART"/cryptpilot-fde-host-0.8.0*.rpm >&2

# grpcurl — needed by verifier/register-shared-as.sh (SetAttestationPolicy on the AS). Not in the
# al8 repos; install the release binary if missing.
GRPCURL_VER="${GRPCURL_VER:-1.9.1}"
command -v grpcurl >/dev/null || {
  echo "==> installing grpcurl $GRPCURL_VER -> /usr/local/bin" >&2
  curl -fsSL "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VER}/grpcurl_${GRPCURL_VER}_linux_x86_64.tar.gz" \
    | tar -xz -C /usr/local/bin grpcurl >&2
}

echo "==> [2/3] build cryptpilot-fde (#128) + get convert (#130) from fork @ ${REF:0:12}" >&2
command -v cargo >/dev/null || { echo "cargo/rust required" >&2; exit 2; }
if [ -d "$SRC/.git" ]; then git -C "$SRC" fetch --depth 1 origin "$REF" 2>/dev/null || git -C "$SRC" fetch origin; else git clone "$REPO" "$SRC" >&2; fi
git -C "$SRC" checkout -q "$REF"
cargo build --release --manifest-path "$SRC/Cargo.toml" -p cryptpilot-fde >&2

echo "==> [3/3] overlay our fixes onto the installed 0.8.0" >&2
install -m0755 "$SRC/cryptpilot-convert.sh"              /usr/bin/cryptpilot-convert       # #130
install -m0755 "$SRC/target/release/cryptpilot-fde-host" /usr/bin/cryptpilot-fde-host      # #128
# sanity
grep -q 'Syncing regenerated grub.cfg to ESP' /usr/bin/cryptpilot-convert || { echo "convert missing #130 ESP-sync" >&2; exit 1; }

echo "[done] toolchain ready (0.8.0 + #128 + #130). guest deb -> FDE_PACKAGE:" >&2
echo "$ART/$GUEST_DEB"
