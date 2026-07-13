#!/usr/bin/env bash
# fetch-inputs.sh <version>
# Stage 0/host inputs for a CI build: base image + target-image cryptpilot-fde deb.
# (tapp-server is fetched by build-gcp-tapp.sh via TAPP_SERVER_URL.)
set -euo pipefail
cd "$(dirname "$0")/.."   # gcp-cvm/

# Cached Stage-0 base (official Ubuntu 24.04 + resize 20G + gVNIC). Prefer a cached artifact;
# override BASE_IMAGE_URL to a GCS/HTTP location, else Stage 0 must have staged base-noble.qcow2.
BASE="${BASE_IMAGE:-base-noble.qcow2}"
BASE_IMAGE_URL="${BASE_IMAGE_URL:-}"
if [ ! -f "$BASE" ]; then
  [ -n "$BASE_IMAGE_URL" ] || { echo "base image $BASE missing and BASE_IMAGE_URL unset (run Stage 0, or point BASE_IMAGE_URL at a cached base)" >&2; exit 1; }
  echo "==> fetching base image: $BASE_IMAGE_URL"
  # NOTE: always COPY, never symlink — Stage A modifies the input image in place, so a symlink
  # would corrupt the cached base.
  case "$BASE_IMAGE_URL" in
    gs://*)   gsutil cp "$BASE_IMAGE_URL" "$BASE" ;;
    file://*) cp -f --sparse=always "${BASE_IMAGE_URL#file://}" "$BASE" ;;
    /*)       cp -f --sparse=always "$BASE_IMAGE_URL" "$BASE" ;;   # absolute local path (persistent runner cache)
    *)        curl -fL "$BASE_IMAGE_URL" -o "$BASE" ;;
  esac
fi

# target-image FDE runtime deb: the 0.8.0 in-image runtime (cryptpilot-fde split into -host/-guest
# at 0.8.0; the image gets -guest). Pinned to the released v0.8.0 asset. #128/#130 do NOT touch the
# runtime, so the released guest deb is used as-is (no fork build needed for the in-image side).
FDE_DEB="${FDE_PACKAGE:-cryptpilot-fde-guest_0.8.0_amd64.deb}"
FDE_DEB_URL="${FDE_DEB_URL:-https://github.com/openanolis/cryptpilot/releases/download/v0.8.0/cryptpilot-fde-guest_0.8.0_amd64.deb}"
[ -f "$FDE_DEB" ] || { echo "==> fetching $FDE_DEB"; curl -fL "$FDE_DEB_URL" -o "$FDE_DEB"; }

echo "[done] base=$BASE fde=$FDE_DEB"
