#!/usr/bin/env bash
# =============================================================================
# Register the boot-chain policy on a SHARED Attestation Service.
# =============================================================================
# The shared AS's RVPS is not externally writable, so reference values cannot be
# registered there. Instead we inject a release×env reference set into a copy of the
# canonical policy.rego and register it under id `0g-tapp-<version>-<env>`.
# (For a self-hosted AS with writable RVPS, register the values to RVPS and use the
#  canonical policy unchanged — see 0g-tapp-verifier.)
#
# Usage:
#   ./register-shared-as.sh <version> <env> [as-endpoint]
#     <version>     e.g. v0.1.0   (→ reference-values/<version>/<env>.json)
#     <env>         dev | prod
#     as-endpoint   default 47.237.201.184:50004
#
# Prereqs: grpcurl, python3, base64; run from the repo (paths are relative to it).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

VERSION="${1:?usage: register-shared-as.sh <version> <env> [as-endpoint]}"
ENV="${2:?usage: register-shared-as.sh <version> <env> [as-endpoint]}"
AS="${3:-47.237.201.184:50004}"
REF="reference-values/${VERSION}/${ENV}.json"
POLICY="verifier/policy.rego"
PROTO_DIR="tapp-common/proto"
POLICY_ID="0g-tapp-${VERSION}-${ENV}"

[ -f "$REF" ]    || { echo "error: reference file not found: $REF"; exit 1; }
[ -f "$POLICY" ] || { echo "error: policy not found: $POLICY"; exit 1; }

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

B64=$(printf '%s' "$INJECTED" | base64 -w0 | tr '+/' '-_' | tr -d '=')
python3 -c 'import json,sys; print(json.dumps({"policy_id":sys.argv[1],"policy":sys.argv[2]}))' \
  "${POLICY_ID}_cpu" "$B64" > /tmp/setp.$$.json
grpcurl -plaintext -import-path "$PROTO_DIR" -proto attestation.proto -d @ \
  "$AS" attestation.AttestationService/SetAttestationPolicy < /tmp/setp.$$.json
rm -f /tmp/setp.$$.json
echo "registered policy ${POLICY_ID} (as ${POLICY_ID}_cpu) on ${AS}"
echo "verify with: tapp-cli verify-app --app-id <id> --as-endpoint ${AS} --policy-ids ${POLICY_ID}"
