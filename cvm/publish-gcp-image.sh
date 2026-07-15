#!/bin/bash
# publish-gcp-image.sh <image.qcow2> <gcp-image-name>
#
# Stage C: turn a built cryptpilot tapp qcow2 into a bootable GCP image. Four steps:
#   [C1] qemu-img convert qcow2 -> raw disk.raw
#   [C2] tar (oldgnu, sparse) -> <name>.tar.gz   (GCP requires an archive whose single member is
#        exactly "disk.raw")
#   [C3] gsutil cp the tarball to the GCS bucket
#   [C4] gcloud compute images create with the confidential-VM guest-os-features
#
# Requires: qemu-img, tar, gsutil, gcloud (authenticated: `gcloud auth login`), and write access to
# the target GCS bucket / project. This step is separate from the image build because it needs cloud
# credentials and network upload; run it after build-tapp.sh (or via that script's opt-in Stage C).
#
# Usage:
#   ./publish-gcp-image.sh /root/og-tdx.qcow2 og-tdx
#   GCS_BUCKET=gs://tapp-image GCP_PROJECT=g-devops ./publish-gcp-image.sh og-tdx-dev.qcow2 og-tdx-dev

set -euo pipefail

IMG="${1:?usage: $0 <image.qcow2> <gcp-image-name>}"
NAME="${2:?usage: $0 <image.qcow2> <gcp-image-name>}"
[ -f "$IMG" ] || { echo "image not found: $IMG" >&2; exit 1; }
# GCP image names: ^[a-z]([-a-z0-9]*[a-z0-9])?$, max 63 chars. The name now carries the owner address
# (~42 chars), so a long version tag could overflow — fail early with a clear message rather than a
# cryptic gcloud error.
[ "${#NAME}" -le 63 ] || { echo "image name '$NAME' is ${#NAME} chars (GCP max 63) — shorten the version tag" >&2; exit 1; }
printf '%s' "$NAME" | grep -Eq '^[a-z]([-a-z0-9]*[a-z0-9])?$' || { echo "image name '$NAME' is not a valid GCP name (^[a-z][-a-z0-9]*[a-z0-9]?$)" >&2; exit 1; }

# ===== Tunables =====
GCS_BUCKET="${GCS_BUCKET:-gs://tapp-image}"
GCP_PROJECT="${GCP_PROJECT:-g-devops}"
GUEST_OS_FEATURES="${GUEST_OS_FEATURES:-UEFI_COMPATIBLE,GVNIC,SEV_CAPABLE,TDX_CAPABLE}"
WORKDIR="${WORKDIR:-$(cd "$(dirname "$IMG")" && pwd)}"   # where disk.raw / tarball are staged
KEEP_TARBALL="${KEEP_TARBALL:-0}"                         # 1 = keep the local .tar.gz after upload
OVERWRITE="${OVERWRITE:-0}"                              # 1 = if the image name exists, delete then recreate
# ====================

for t in qemu-img tar gsutil gcloud; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done

RAW="$WORKDIR/disk.raw"
TAR="$WORKDIR/$NAME.tar.gz"

# An existing image name is immutable by default (a published version image may back running
# instances; silently replacing it would change its measurements and break their attestation).
# OVERWRITE=1 opts into delete-then-recreate for deliberate re-runs of the same version.
if gcloud compute images describe "$NAME" --project="$GCP_PROJECT" >/dev/null 2>&1; then
  if [ "$OVERWRITE" = 1 ]; then
    echo "==> image '$NAME' already exists; OVERWRITE=1 → deleting it first"
    gcloud compute images delete "$NAME" --project="$GCP_PROJECT" --quiet
  else
    echo "GCP image '$NAME' already exists in project $GCP_PROJECT." >&2
    echo "  re-run with OVERWRITE=1 to replace it, delete it manually, or publish under a new name." >&2
    echo "  delete:  gcloud compute images delete $NAME --project=$GCP_PROJECT" >&2
    exit 1
  fi
fi

cleanup() { rm -f "$RAW"; [ "$KEEP_TARBALL" = 1 ] || rm -f "$TAR"; }
trap cleanup EXIT

echo "==> [C1] qemu-img convert qcow2 -> raw ($RAW)"
qemu-img convert -p -f qcow2 -O raw "$IMG" "$RAW"

echo "==> [C2] tar (oldgnu, sparse) -> $TAR"
# -C so the archive member is exactly "disk.raw" (GCP requirement), -S to keep the sparse raw small
tar --format=oldgnu -Szcf "$TAR" -C "$WORKDIR" disk.raw

echo "==> [C3] upload -> $GCS_BUCKET/"
gsutil cp "$TAR" "$GCS_BUCKET/"

echo "==> [C4] create GCP image '$NAME' (project $GCP_PROJECT, features $GUEST_OS_FEATURES)"
gcloud compute images create "$NAME" \
  --project="$GCP_PROJECT" \
  --source-uri="$GCS_BUCKET/$(basename "$TAR")" \
  --guest-os-features="$GUEST_OS_FEATURES"

echo ""
echo "[done] GCP image: $NAME  (project $GCP_PROJECT)"
echo "  create an instance with:  --image=$NAME --image-project=$GCP_PROJECT --confidential-compute-type=TDX"
