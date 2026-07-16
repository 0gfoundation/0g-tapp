#!/bin/bash
# publish-ali-image.sh <image.qcow2> <ali-image-name>
#
# Stage C (Alibaba Cloud): turn a built cryptpilot tapp UKI qcow2 into a bootable Ali custom image.
#   [C1] ossutil cp the qcow2 to an OSS bucket
#   [C2] aliyun ecs ImportImage from that OSS object
#   [C3] enable NVMe support on the imported image  (MUST be set AFTER ImportImage is kicked off)
#   [C4] wait until the image Status = Available
#
# The four params that are easy to get wrong (per the Ali confidential-disk guide) are pinned here:
#   * Architecture = x86_64           (64-bit OS)
#   * BootMode     = UEFI             (cryptpilot UKI boots via UEFI/systemd-boot)
#   * Format       = QCOW2
#   * NVMe support = supported        (set after import — the confidential instance uses NVMe disks)
#
# Requires: ossutil + aliyun (both authenticated — set ALIBABA_CLOUD_ACCESS_KEY_ID /
# ALIBABA_CLOUD_ACCESS_KEY_SECRET, and configure ossutil, e.g. via `ossutil config` or its env vars),
# and write access to the OSS bucket + ECS ImportImage in the target region. Analogous to
# publish-gcp-image.sh (which needs gcloud/gsutil); the CI auth step provisions the Ali credentials.
#
# Usage:
#   ALIYUN_REGION=cn-beijing ./publish-ali-image.sh ./og-tdx-ali-dev-v0-1-0.qcow2 og-tdx-ali-dev-v0-1-0
set -euo pipefail

IMG="${1:?usage: $0 <image.qcow2> <ali-image-name>}"
NAME="${2:?usage: $0 <image.qcow2> <ali-image-name>}"
[ -f "$IMG" ] || { echo "image not found: $IMG" >&2; exit 1; }

# ===== Tunables =====
OSS_BUCKET="${OSS_BUCKET:-0g-confidential-disk}"          # OSS bucket NAME (no oss:// prefix)
ALIYUN_REGION="${ALIYUN_REGION:?ALIYUN_REGION is required, e.g. cn-beijing}"
OSS_OBJECT="${OSS_OBJECT:-${NAME}.qcow2}"                 # object key in the bucket
OSS_ENDPOINT="${OSS_ENDPOINT:-oss-${ALIYUN_REGION}.aliyuncs.com}"
PLATFORM="${PLATFORM:-Ubuntu}"
KEEP_OSS_OBJECT="${KEEP_OSS_OBJECT:-0}"                   # 1 = keep the uploaded qcow2 in OSS after import
POLL_MAX="${POLL_MAX:-1800}"                              # max seconds to wait for the image to become Available
OVERWRITE="${OVERWRITE:-0}"                              # 1 = if the image name exists, delete then recreate
# ====================

for t in ossutil aliyun python3; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done

# An existing image name is immutable by default (a published version image may back running
# instances; silently replacing it would change its measurements and break their attestation).
# OVERWRITE=1 opts into delete-then-recreate for deliberate re-runs of the same version.
EXIST_ID="$(aliyun ecs DescribeImages --RegionId "$ALIYUN_REGION" --ImageName "$NAME" 2>/dev/null \
  | python3 -c 'import sys,json; im=json.load(sys.stdin).get("Images",{}).get("Image",[]); print(im[0]["ImageId"] if im else "")')"
if [ -n "$EXIST_ID" ]; then
  if [ "$OVERWRITE" = 1 ]; then
    echo "==> image '$NAME' already exists ($EXIST_ID); OVERWRITE=1 → deleting it first"
    aliyun ecs DeleteImage --RegionId "$ALIYUN_REGION" --ImageId "$EXIST_ID" --Force true >/dev/null
  else
    echo "Ali image '$NAME' already exists in region $ALIYUN_REGION ($EXIST_ID)." >&2
    echo "  re-run with OVERWRITE=1 to replace it, delete it manually, or publish under a new name." >&2
    exit 1
  fi
fi

echo "==> [C1] ossutil cp -> oss://$OSS_BUCKET/$OSS_OBJECT"
ossutil cp -f "$IMG" "oss://$OSS_BUCKET/$OSS_OBJECT"

echo "==> [C2] aliyun ecs ImportImage (Architecture=x86_64, BootMode=UEFI, Format=QCOW2)"
IMPORT_JSON="$(aliyun ecs ImportImage \
  --RegionId "$ALIYUN_REGION" \
  --ImageName "$NAME" \
  --Platform "$PLATFORM" \
  --OSType linux \
  --Architecture x86_64 \
  --BootMode UEFI \
  --DiskDeviceMapping.1.OSSBucket "$OSS_BUCKET" \
  --DiskDeviceMapping.1.OSSObject "$OSS_OBJECT" \
  --DiskDeviceMapping.1.Format QCOW2)"
IMAGE_ID="$(printf '%s' "$IMPORT_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["ImageId"])')"
echo "    ImageId=$IMAGE_ID"

echo "==> [C3] enable NVMe support (ModifyImageAttribute Features.NvmeSupport=supported)"
# The confidential instance exposes disks over NVMe; the imported image must advertise NVMe support.
# --force: the aliyun CLI's built-in schema for ModifyImageAttribute doesn't expose the Features.NvmeSupport
# sub-field as a flag (rejects both `--Features.NvmeSupport` and JSON `--Features`), so --force skips
# client-side validation and sends it in the flat form the server requires. Verified working.
aliyun ecs ModifyImageAttribute \
  --RegionId "$ALIYUN_REGION" \
  --ImageId "$IMAGE_ID" \
  --Features.NvmeSupport supported --force >/dev/null

echo "==> [C4] wait for image $IMAGE_ID to become Available (import task runs async; up to ${POLL_MAX}s)"
# NOTE: DescribeImages defaults to Status=Available, so an importing image (Status=Creating) returns
# NOTHING — an empty result means "still importing / not visible yet", NOT failure. Ask for the
# in-progress statuses explicitly, and only treat CreateFailed (or the timeout) as fatal.
t=0
while :; do
  status="$(aliyun ecs DescribeImages --RegionId "$ALIYUN_REGION" --ImageId "$IMAGE_ID" \
    --Status Creating,Waiting,Available,CreateFailed 2>/dev/null \
    | python3 -c 'import sys,json; im=json.load(sys.stdin).get("Images",{}).get("Image",[]); print(im[0]["Status"] if im else "Pending")')"
  case "$status" in
    Available) echo "    image is Available"; break ;;
    CreateFailed) echo "!! import failed (status=CreateFailed)" >&2; exit 1 ;;
    *) [ "$t" -ge "$POLL_MAX" ] && { echo "!! timed out waiting (last status=$status)" >&2; exit 1; }
       sleep 20; t=$((t+20)); echo "    status=$status (${t}s)" ;;
  esac
done

[ "$KEEP_OSS_OBJECT" = 1 ] || { echo "==> cleanup: rm oss://$OSS_BUCKET/$OSS_OBJECT"; ossutil rm -f "oss://$OSS_BUCKET/$OSS_OBJECT" >/dev/null 2>&1 || true; }

echo ""
echo "[done] Ali image: $NAME  (ImageId=$IMAGE_ID, region $ALIYUN_REGION)"
echo "  create a confidential (TDX) instance from it; assign a public IPv4 (for Trustee attestation)"
echo "  and use key-pair auth (passwords are unsupported on confidential instances)."
