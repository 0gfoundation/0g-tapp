#!/usr/bin/env bash
# =============================================================================
# Register the boot-chain policy on a SHARED Attestation Service.
# =============================================================================
# The shared AS's RVPS is not externally writable, so reference values cannot be
# registered there. Instead we inject a reference set into a copy of the canonical
# policy.rego and register it under a version-scoped policy id.
#
# Two modes (matching build modes):
#   canonical (owner omitted): one policy for all owners; reads <env>.json
#     → policy id: 0g-tapp-<cloud>-<boot_format>-<version>-<env>
#   custom    (owner given):   per-owner policy; reads <env>/<owner>.json
#     → policy id: 0g-tapp-<cloud>-<boot_format>-<version>-<env>-<owner>
#
# Usage:
#   ./register-shared-as.sh <cloud> <boot_format> <version> <env> [owner] [as-endpoint]
#     owner       optional: OWNER_ADDRESS (0x...); omit for canonical mode
#     as-endpoint default https://35.253.66.70:50004 (https:// selects TLS; host:port stays plaintext)
#
# Env:
#   AS_WRITE_KEY  optional: bearer key for a gated AS (issue #82). The hosted deployment
#                 keeps the AS on an internal network behind a proxy that allows
#                 AttestationEvaluate/GetAttestationChallenge but requires a key for this
#                 write; keys are issued against the registry's on-chain admin signature,
#                 expire and can be revoked. Unset = today's behaviour, and an AS that
#                 requires no key ignores the header — so this is safe in both directions.
#
# Prereqs: grpcurl, python3, base64; run from the repo (paths are relative to it).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

U="usage: register-shared-as.sh <cloud> <boot_format> <version> <env> [owner] [as-endpoint]"
CLOUD="${1:?$U}"
BOOT_FORMAT="${2:?$U}"
VERSION="${3:?$U}"
ENV="${4:?$U}"
# Detect whether arg 5 looks like an owner address or an AS endpoint
_ARG5="${5:-}"
if printf '%s' "$_ARG5" | grep -qE '^(0[xX])?[0-9a-fA-F]{40}$'; then
  OWNER="$(printf '%s' "$_ARG5" | sed 's/^0[xX]//' | tr 'A-Z' 'a-z')"
  AS="${6:-https://35.253.66.70:50004}"
else
  OWNER=""
  AS="${_ARG5:-https://35.253.66.70:50004}"
fi

if [ -n "$OWNER" ]; then
  REF="verifier/reference-values/${CLOUD}/${BOOT_FORMAT}/${VERSION}/${ENV}/${OWNER}.json"
  POLICY_ID="0g-tapp-${CLOUD}-${BOOT_FORMAT}-${VERSION}-${ENV}-${OWNER}"
else
  REF="verifier/reference-values/${CLOUD}/${BOOT_FORMAT}/${VERSION}/${ENV}.json"
  POLICY_ID="0g-tapp-${CLOUD}-${BOOT_FORMAT}-${VERSION}-${ENV}"
fi
POLICY="verifier/policy.rego"
PROTO_DIR="tapp-common/proto"

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
# grub uses 5 components, uki uses 1 — inject a literal set per rule (empty set() when
# the key is absent), so whichever format the image is, only its boot_chain_ok branch
# in policy.rego has non-empty reference sets and fires. Require ≥1 value overall.
keymap = {
    "ref_shim": "measurement.shim.SHA-384",
    "ref_grub": "measurement.grub.SHA-384",
    "ref_kernel": "measurement.kernel.SHA-384",
    "ref_initrd": "measurement.initrd.SHA-384",
    "ref_kernel_cmdline": "measurement.kernel_cmdline.SHA-384",
    "ref_uki": "measurement.uki.SHA-384",
}
nonempty = 0
for rule, key in keymap.items():
    vals = [v for v in ref.get(key, []) if isinstance(v, str) and v]
    nonempty += len(vals)
    literal = ("{" + ", ".join('"%s"' % v for v in vals) + "}") if vals else "set()"
    # replace the rule's RHS (the qrv(...) set comprehension) with the literal set
    policy, n = re.subn(rule + r" := \{x \| some x in qrv\([^)]*\)\}", f"{rule} := {literal}", policy, count=1)
    if n != 1:
        sys.stderr.write(f"error: could not inject {rule} (policy.rego rule/regex mismatch)\n"); sys.exit(1)
if nonempty == 0:
    sys.stderr.write("error: reference file has no measurement.*.SHA-384 values\n"); sys.exit(1)
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
# Bearer key for a gated AS. Kept in an array so an unset key adds no argument at all
# (an empty -H "" would be sent as a malformed header rather than omitted).
AUTH=()
if [ -n "${AS_WRITE_KEY:-}" ]; then
  AUTH=(-H "authorization: Bearer ${AS_WRITE_KEY}")
  echo "using AS_WRITE_KEY for the write call"
fi
# ${AUTH[@]+"${AUTH[@]}"}: expands to nothing when AUTH is empty, and does not trip
# `set -u` on bash < 4.4 (macOS ships 3.2, where a bare "${AUTH[@]}" is an unbound variable).
# The shared AS serves TLS with a self-signed, attested certificate, so -insecure is
# required: no CA will ever vouch for it. That leaves this call unauthenticated, which is
# acceptable only because SetAttestationPolicy is already gated on a bearer key the AS
# checks — the transport is not what authorises the write. A local plaintext AS still
# works: pass it as host:port and TLS is skipped entirely.
TLS=(-plaintext)
AS_SHOWN="$AS"          # keep the scheme for the hint printed at the end
case "$AS" in https://*) TLS=(-insecure); AS="${AS#https://}" ;; esac

grpcurl "${TLS[@]}" ${AUTH[@]+"${AUTH[@]}"} -import-path "$PROTO_DIR" -proto attestation.proto -d @ \
  "$AS" attestation.AttestationService/SetAttestationPolicy < "$TMP"
echo "registered policy ${POLICY_ID} (as ${POLICY_ID}_cpu) on ${AS}"
echo "verify with: tapp-cli verify-app --app-id <id> --as-endpoint ${AS_SHOWN} --policy-ids ${POLICY_ID}"
