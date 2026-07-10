#!/usr/bin/env bash
# gen-reference-values.sh <image.qcow2> <version> <env> <owner>
#
# Compute the boot-chain reference values from a built image and write them to
#   verifier/reference-values/<version>/<env>/<owner>.json
# in the schema policy.rego consumes ("measurement.<component>.SHA-384": [<hex>...]).
#
# MUST run on an Alinux/al8 host, and cryptpilot-fde MUST be the #128-fixed build:
# stock 0.7.0 errors "saved_entry not found in GRUB environment" on a freshly built
# (never-booted) image — see gcp-cvm/cryptpilot-gcp-boot-fix.md §7.6/§12.
#
# NOTE (draft): the extraction below greps `cryptpilot-fde show-reference-value` output
# by component name. Confirm the exact labels/format against a real run on the fixed
# binary and adjust the `pick()` patterns if needed — the script FAILS if any of the
# five components is missing, so it will never emit a half-populated file.

set -euo pipefail

IMG="${1:?usage: $0 <image.qcow2> <version> <env> <owner>}"
VERSION="${2:?usage: $0 <image.qcow2> <version> <env> <owner>}"
ENV="${3:?usage: $0 <image.qcow2> <version> <env> <owner>}"
OWNER="$(printf '%s' "${4:?usage: $0 <image.qcow2> <version> <env> <owner>}" | tr 'A-Z' 'a-z')"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$REPO/verifier/reference-values/${VERSION}/${ENV}"
OUT="$OUT_DIR/${OWNER}.json"
RAW="$(mktemp)"; trap 'rm -f "$RAW"' EXIT

command -v cryptpilot-fde >/dev/null || { echo "cryptpilot-fde not found (Alinux host + #128 fix required)" >&2; exit 2; }

echo "==> cryptpilot-fde show-reference-value --disk $IMG"
cryptpilot-fde show-reference-value --disk "$IMG" --hash-algo sha384 > "$RAW" 2>&1 || {
  echo "show-reference-value failed:" >&2; cat "$RAW" >&2
  echo "(if 'saved_entry not found' → stock 0.7.0; build the #128-fixed cryptpilot-fde, see §12)" >&2
  exit 1
}

mkdir -p "$OUT_DIR"
python3 - "$RAW" "$OUT" <<'PY'
import sys, re, json
raw = open(sys.argv[1]).read()
# component -> json key. kernel_cmdline may legitimately have several allowed hashes.
COMPONENTS = {
    "shim":           "measurement.shim.SHA-384",
    "grub":           "measurement.grub.SHA-384",
    "kernel":         "measurement.kernel.SHA-384",
    "initrd":         "measurement.initrd.SHA-384",
    "kernel_cmdline": "measurement.kernel_cmdline.SHA-384",
}
def pick(name):
    # collect every 96-hex-char SHA-384 that appears on a line mentioning the component.
    # CONFIRM against real output; adjust the line match if the fixed binary formats differently.
    vals = []
    for line in raw.splitlines():
        if re.search(rf'\b{re.escape(name)}\b', line, re.I):
            vals += re.findall(r'\b[0-9a-fA-F]{96}\b', line)
    # de-dup, keep order
    seen, out = set(), []
    for v in (v.lower() for v in vals):
        if v not in seen: seen.add(v); out.append(v)
    return out

ref, missing = {}, []
for name, key in COMPONENTS.items():
    vals = pick(name)
    if not vals: missing.append(name)
    ref[key] = vals
if missing:
    sys.stderr.write("ERROR: could not extract reference values for: %s\n" % ", ".join(missing))
    sys.stderr.write("---- raw show-reference-value output ----\n" + raw + "\n")
    sys.exit(1)
json.dump(ref, open(sys.argv[2], "w"), indent=2)
open(sys.argv[2], "a").write("\n")
print("wrote", sys.argv[2])
PY
echo "[done] $OUT"
