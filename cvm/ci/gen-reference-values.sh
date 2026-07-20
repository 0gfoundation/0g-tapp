#!/usr/bin/env bash
# gen-reference-values.sh <image.qcow2> <cloud> <boot_format> <version> <env> [owner]
#
# Compute the boot-chain reference values from a built image and write:
#   canonical (owner omitted): verifier/reference-values/<cloud>/<boot_format>/<version>/<env>.json
#   custom    (owner given):   verifier/reference-values/<cloud>/<boot_format>/<version>/<env>/<owner>.json
# in the schema policy.rego consumes ("measurement.<component>.SHA-384": [<hex>...]).
#
# Uses a #128-fixed cryptpilot-fde (0.8.0+), which on a never-booted image (empty grubenv)
# falls back to the default grub.cfg menuentry instead of erroring "saved_entry not found"
# (see cvm/cryptpilot-gcp-boot-fix.md §7.6/§12). The tool already emits JSON with the
# exact "measurement.*.SHA-384" keys; we just drop its non-"measurement." helper keys.
#
# The binary is /usr/bin/cryptpilot-fde-host, set up by ci/setup-toolchain.sh (released 0.8.0 with
# our #128 build overlaid), overridable via $CRYPTPILOT_FDE. MUST run on an Alinux/al8 host.

set -euo pipefail

U="usage: $0 <image.qcow2> <cloud> <boot_format> <version> <env> [owner]"
IMG="${1:?$U}"
CLOUD="${2:?$U}"
BOOT_FORMAT="${3:?$U}"
VERSION="${4:?$U}"
ENV="${5:?$U}"
# owner optional: omit for canonical mode (no owner baked in the image)
OWNER="$(printf '%s' "${6:-}" | sed 's/^0[xX]//' | tr 'A-Z' 'a-z')"

FDE="${CRYPTPILOT_FDE:-/usr/bin/cryptpilot-fde-host}"
[ -x "$FDE" ] || { echo "cryptpilot-fde-host not found at $FDE — run ci/setup-toolchain.sh first" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
REFVAL_BASE="$REPO/verifier/reference-values/${CLOUD}/${BOOT_FORMAT}/${VERSION}"

if [ -n "$OWNER" ]; then
  # custom: .../v0.3.0/<env>/<owner>.json
  OUT="$REFVAL_BASE/${ENV}/${OWNER}.json"
else
  # canonical: .../v0.3.0/<env>.json  (no owner subdirectory)
  OUT="$REFVAL_BASE/${ENV}.json"
fi

RAW="$(mktemp)"; trap 'rm -f "$RAW"' EXIT

echo "==> $FDE show-reference-value --disk $IMG"
"$FDE" show-reference-value --disk "$IMG" --hash-algo sha384 >"$RAW" 2>/tmp/srv.err || {
  echo "show-reference-value failed:" >&2; cat /tmp/srv.err >&2; exit 1
}

mkdir -p "$(dirname "$OUT")"
# keep only the measurement.<component>.SHA-384 keys; require ≥1, else fail.
python3 - "$RAW" "$OUT" <<'PY'
import sys, json
data = json.load(open(sys.argv[1]))
out = {k: v for k, v in data.items()
       if k.startswith("measurement.") and k.endswith(".SHA-384") and isinstance(v, list) and v}
if not out:
    sys.stderr.write("ERROR: no non-empty measurement.*.SHA-384 in show-reference-value output\n")
    sys.stderr.write("---- raw ----\n" + json.dumps(data, indent=2) + "\n")
    sys.exit(1)
json.dump(out, open(sys.argv[2], "w"), indent=2)
open(sys.argv[2], "a").write("\n")
PY
echo "[done] $OUT"; cat "$OUT"
