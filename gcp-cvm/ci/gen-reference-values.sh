#!/usr/bin/env bash
# gen-reference-values.sh <image.qcow2> <version> <env> <owner>
#
# Compute the boot-chain reference values from a built image and write
#   verifier/reference-values/<version>/<env>/<owner>.json
# in the schema policy.rego consumes ("measurement.<component>.SHA-384": [<hex>...]).
#
# Uses a #128-fixed cryptpilot-fde (0.8.0+), which on a never-booted image (empty grubenv)
# falls back to the default grub.cfg menuentry instead of erroring "saved_entry not found"
# (see gcp-cvm/cryptpilot-gcp-boot-fix.md §7.6/§12). The tool already emits JSON with the
# exact "measurement.*.SHA-384" keys; we just drop its non-"measurement." helper keys.
#
# The binary is taken from $CRYPTPILOT_FDE — the pipeline builds it from a pinned fork
# commit (ci/build-cryptpilot-fde.sh) for transparency rather than shipping a prebuilt blob.
# MUST run on an Alinux/al8 host.

set -euo pipefail

IMG="${1:?usage: $0 <image.qcow2> <version> <env> <owner>}"
VERSION="${2:?usage: $0 <image.qcow2> <version> <env> <owner>}"
ENV="${3:?usage: $0 <image.qcow2> <version> <env> <owner>}"
OWNER="$(printf '%s' "${4:?usage: $0 <image.qcow2> <version> <env> <owner>}" | tr 'A-Z' 'a-z')"

FDE="${CRYPTPILOT_FDE:?set CRYPTPILOT_FDE to the #128-fixed cryptpilot-fde-host (build via ci/build-cryptpilot-fde.sh)}"
[ -x "$FDE" ] || { echo "CRYPTPILOT_FDE not executable: $FDE" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$REPO/verifier/reference-values/${VERSION}/${ENV}"
OUT="$OUT_DIR/${OWNER}.json"
RAW="$(mktemp)"; trap 'rm -f "$RAW"' EXIT

echo "==> $FDE show-reference-value --disk $IMG"
"$FDE" show-reference-value --disk "$IMG" --hash-algo sha384 >"$RAW" 2>/tmp/srv.err || {
  echo "show-reference-value failed:" >&2; cat /tmp/srv.err >&2; exit 1
}

mkdir -p "$OUT_DIR"
# keep only the five measurement.<component>.SHA-384 keys (drop the raw "kernel_cmdline" echo etc.);
# require every one to be a non-empty array, else fail loudly (never emit a half-populated file).
python3 - "$RAW" "$OUT" <<'PY'
import sys, json
data = json.load(open(sys.argv[1]))
KEYS = [
    "measurement.shim.SHA-384",
    "measurement.grub.SHA-384",
    "measurement.kernel.SHA-384",
    "measurement.initrd.SHA-384",
    "measurement.kernel_cmdline.SHA-384",
]
out, missing = {}, []
for k in KEYS:
    v = data.get(k)
    if not (isinstance(v, list) and v):
        missing.append(k)
    out[k] = v
if missing:
    sys.stderr.write("ERROR: empty/missing reference components: %s\n" % ", ".join(missing))
    sys.stderr.write("---- raw ----\n" + json.dumps(data, indent=2) + "\n")
    sys.exit(1)
json.dump(out, open(sys.argv[2], "w"), indent=2)
open(sys.argv[2], "a").write("\n")
PY
echo "[done] $OUT"; cat "$OUT"
