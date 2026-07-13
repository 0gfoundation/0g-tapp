#!/usr/bin/env bash
# build-cryptpilot-fde.sh [out-dir]
#
# Compile the #128-fixed cryptpilot-fde-host from the 0gfoundation cryptpilot fork, from source,
# at a PINNED commit — so the reference-value tool is transparent/reproducible rather than a
# prebuilt blob. Prints the resulting cryptpilot-fde-host path on stdout (last line).
#
# Why a fork build: stock cryptpilot-fde 0.7.0's `show-reference-value` errors "saved_entry not
# found" on a never-booted image (empty grubenv). The pinned fork commit falls back to the default
# grub.cfg menuentry instead. See gcp-cvm/cryptpilot-gcp-boot-fix.md §7.6/§12.
#
# Prereqs (Alinux/al8): git, cargo/rust, and cryptsetup-devel (build dep).

set -euo pipefail

REPO_URL="${CRYPTPILOT_REPO_URL:-https://github.com/0gfoundation/cryptpilot.git}"
# Pinned to the fork commit that carries the show-reference-value fallback fix (branch
# fix/srv-default-entry) — falls back to the default grub.cfg menuentry when grubenv has no
# saved_entry, and supports --hash-algo. Bump deliberately; do not track a moving branch.
# NB: NOT fix/gcp-convert-esp-sync (52a77a2) — that's the convert-side ESP fix and lacks the fallback.
REF="${CRYPTPILOT_REF:-64fe4e744574c8e0273dd1e5d54ceae9714748a0}"
OUT_DIR="${1:-$HOME/.cache/cvm-ci/cryptpilot}"

command -v cargo >/dev/null || { echo "cargo/rust required" >&2; exit 2; }
rpm -q cryptsetup-devel >/dev/null 2>&1 || echo "warn: cryptsetup-devel not found via rpm -q; build may fail (dnf install -y cryptsetup-devel)" >&2

mkdir -p "$OUT_DIR"
if [ -d "$OUT_DIR/.git" ]; then
  git -C "$OUT_DIR" fetch --depth 1 origin "$REF" 2>/dev/null || git -C "$OUT_DIR" fetch origin
else
  git clone "$REPO_URL" "$OUT_DIR"
fi
git -C "$OUT_DIR" checkout -q "$REF"
echo "==> building cryptpilot-fde @ $(git -C "$OUT_DIR" rev-parse --short HEAD)" >&2
cargo build --release --manifest-path "$OUT_DIR/Cargo.toml" -p cryptpilot-fde >&2

BIN="$OUT_DIR/target/release/cryptpilot-fde-host"
[ -x "$BIN" ] || { echo "expected binary not built: $BIN" >&2; exit 1; }
"$BIN" --version >&2
echo "$BIN"
