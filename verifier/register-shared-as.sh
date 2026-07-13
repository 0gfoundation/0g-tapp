#!/usr/bin/env bash
# =============================================================================
# Register the boot-chain policy on a SHARED Attestation Service.
# =============================================================================
# The shared AS's RVPS is not externally writable, so reference values cannot be
# registered there. Instead we inject a release×env×owner reference set into a copy of
# the canonical policy.rego and register it under id `0g-tapp-<version>-<env>-<owner>`.
# (For a self-hosted AS with writable RVPS, register the values to RVPS and use the
#  canonical policy unchanged — see 0g-tapp-verifier.)
#
# `owner` is a dimension because OWNER_ADDRESS is baked into /etc/tapp/config.toml, which
# lives on the verity rootfs; policy.rego folds rootfs integrity into the initrd
# measurement, so a different owner ⇒ a different measurement.initrd ⇒ a distinct
# reference set. See verifier/reference-values/README.md.
#
# Usage:
#   ./register-shared-as.sh <cloud> <version> <env> <owner> [as-endpoint]
#     <cloud>       gcp | ali   (→ verifier/reference-values/<cloud>/<version>/<env>/<owner>.json)
#     <version>     e.g. v0.1.0
#     <env>         dev | prod
#     <owner>       OWNER_ADDRESS (0x...); normalized to lowercase for the path/id
#     as-endpoint   default 47.237.201.184:50004
#   → registers policy 0g-tapp-<cloud>-<version>-<env>-<owner> (each cloud is a distinct image
#     with its own boot-chain measurements, so cloud is a real dimension, not just a label)
#
# Prereqs: grpcurl, python3, base64; run from the repo (paths are relative to it).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CLOUD="${1:?usage: register-shared-as.sh <cloud> <version> <env> <owner> [as-endpoint]}"
VERSION="${2:?usage: register-shared-as.sh <cloud> <version> <env> <owner> [as-endpoint]}"
ENV="${3:?usage: register-shared-as.sh <cloud> <version> <env> <owner> [as-endpoint]}"
OWNER="${4:?usage: register-shared-as.sh <cloud> <version> <env> <owner> [as-endpoint]}"
OWNER="$(printf '%s' "$OWNER" | tr 'A-Z' 'a-z')"   # normalize (addresses are case-insensitive)
AS="${5:-47.237.201.184:50004}"
REF="verifier/reference-values/${CLOUD}/${VERSION}/${ENV}/${OWNER}.json"
POLICY="verifier/policy.rego"
PROTO_DIR="tapp-common/proto"
POLICY_ID="0g-tapp-${CLOUD}-${VERSION}-${ENV}-${OWNER}"

[ -f "$REF" ]    || { echo "error: reference file not found: $REF"; exit 1; }
[ -f "$POLICY" ] || { echo "error: policy not found: $POLICY"; exit 1; }
if grep -q '"_TODO"' "$REF"; then
	echo "error: $REF is a placeholder — fill in the reference values first" >&2
	exit 1
fi

# Inject the reference values: replace each `ref_X := {x | some x in qrv("...")}`
# line in the canonical policy with a literal set from the json.
INJECTED=$(python3 - "$POLICY" "$REF" <<'PY'
import sys, json, re
policy = open(sys.argv[1]).read()
ref = json.load(open(sys.argv[2]))
keymap = {
    "ref_shim": "measurement.shim.SHA-384",
    "ref_grub": "measurement.grub.SHA-384",
    "ref_kernel": "measurement.kernel.SHA-384",
    "ref_initrd": "measurement.initrd.SHA-384",
    "ref_kernel_cmdline": "measurement.kernel_cmdline.SHA-384",
}
for rule, key in keymap.items():
    vals = [v for v in ref.get(key, []) if isinstance(v, str) and v]
    if not vals:
        sys.stderr.write(f"error: {key} empty in reference file\n"); sys.exit(1)
    literal = "{" + ", ".join('"%s"' % v for v in vals) + "}"
    # replace the rule's RHS (the qrv(...) set comprehension) with the literal set
    policy = re.sub(rule + r" := \{x \| some x in qrv\([^)]*\)\}", f"{rule} := {literal}", policy, count=1)
sys.stdout.write(policy)
PY
)

# Guard: if a ref_* line no longer matches the regex (renamed loop var, whitespace, etc.),
# injection silently no-ops and the values never land. Detect leftover qrv() calls on the
# ref_* assignment lines only — the qrv(key) helper definition legitimately keeps its own.
if printf '%s\n' "$INJECTED" | grep '^ref_' | grep -q 'qrv('; then
	echo "error: a ref_* line still calls qrv() after injection — policy.rego format" >&2
	echo "       changed; update the ref_* regex in this script to match." >&2
	exit 1
fi

TMP="/tmp/setp.$$.json"
trap 'rm -f "$TMP"' EXIT
B64=$(printf '%s' "$INJECTED" | base64 -w0 | tr '+/' '-_' | tr -d '=')
python3 -c 'import json,sys; print(json.dumps({"policy_id":sys.argv[1],"policy":sys.argv[2]}))' \
  "${POLICY_ID}_cpu" "$B64" > "$TMP"
grpcurl -plaintext -import-path "$PROTO_DIR" -proto attestation.proto -d @ \
  "$AS" attestation.AttestationService/SetAttestationPolicy < "$TMP"
echo "registered policy ${POLICY_ID} (as ${POLICY_ID}_cpu) on ${AS}"
echo "verify with: tapp-cli verify-app --app-id <id> --as-endpoint ${AS} --policy-ids ${POLICY_ID}"
