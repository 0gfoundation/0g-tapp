#!/usr/bin/env python3
"""
tapp node verifier. The only input is an app_id; everything else is automatic:
read the chain, fetch evidence, verify the quote at the AS, reconcile the two.
Mirrors steps 1-4 of docs/EVIDENCE_AND_AS_VERIFICATION.md.

Requires: cast (foundry), tapp-cli, grpcurl, and attestation.proto alongside this file.
Usage: python3 verify_app.py <app_id>

Environment overrides: CAST, TAPP_CLI, REGISTRY, RPC_URL, AS_ENDPOINT.
Two TappRegistry deployments exist and an app lives on exactly one of them, so
REGISTRY has to name the right one. See contract/CONTRACTS.md.
"""
import sys, os, json, base64, struct, subprocess, re, binascii, hashlib, secrets

APP   = sys.argv[1] if len(sys.argv) > 1 else "0g-agentic-id-attestor"
CAST  = os.environ.get("CAST", "cast")
CLI   = os.environ.get("TAPP_CLI", "tapp-cli")
C     = os.environ.get("REGISTRY", "0x2Ce80374318B1d7Fb3345724457a182E0ad165c9")  # TappRegistry (0G testnet)
R     = os.environ.get("RPC_URL", "https://evmrpc-testnet.0g.ai")
AS    = os.environ.get("AS_ENDPOINT", "34.171.164.181:50004")   # CoCo-AS gRPC, verifies evidence
PROTO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attestation.proto")
ALG   = {4: 20, 0xb: 32, 0xc: 48, 0xd: 64}
print(f"### verifying app_id = {APP}\n")

def cast_call(sig, *args):
    out = subprocess.run([CAST, "call", C, sig, *args, "--rpc-url", R],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout.strip()

def split_top(s):                       # split on top-level commas, respecting () and []
    parts, d, cur = [], 0, ""
    for ch in s:
        if ch in "([": d += 1
        elif ch in ")]": d -= 1
        if ch == "," and d == 0:
            parts.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts

# ───────── 1. read the registration off the chain ─────────
print("## 1. chain")
ai = cast_call("getAppInfo(string)((bytes,bytes,bytes[],address,uint256))", APP)
f = split_top(ai.strip()[1:-1])
app_compose_hex   = f[0][2:]                      # app-level shared defaults
app_volumes_bytes = bytes.fromhex(f[1][2:]) if f[1] != "0x" else b""
images            = [bytes.fromhex(x.strip()[2:]).decode("utf-8", "replace")
                     for x in f[2][1:-1].split(",") if x.strip()]
print(f"  composeHash = {app_compose_hex}  (app-level default)")
print(f"  imageHashes = {sorted(set(images))}")
nodes = re.findall(r"0x[0-9a-fA-F]{40}", cast_call("getNodeList(string)(address[])", APP))
print(f"  nodeList    = {nodes}")
if not nodes:
    print("FAIL: app is not on chain, stopping."); sys.exit(1)

all_ok = True
for signer in nodes:
    print(f"\n## node {signer}")
    # getNode returns this node's EFFECTIVE compose/volumes: its own per-node override if
    # it set one, otherwise the contract resolves the app-level default in. Reconcile
    # against these, not against getAppInfo's defaults — where an override exists the two
    # differ and using the app-level value reports a spurious failure.
    ni = cast_call("getNode(string,address)((string,uint256,uint256,bytes,bytes))", APP, signer)
    nf = split_top(ni.strip()[1:-1])
    teeUrl = nf[0].strip().strip('"')
    compose_hex   = nf[3][2:] if len(nf) > 3 and nf[3] != "0x" else app_compose_hex
    volumes_bytes = bytes.fromhex(nf[4][2:]) if len(nf) > 4 and nf[4] != "0x" else app_volumes_bytes
    print(f"  teeUrl = {teeUrl}")
    if compose_hex != app_compose_hex:
        print(f"  note: this node overrides composeHash: {compose_hex}")

    # ───────── 2. fetch evidence ─────────
    # A fresh nonce per node: a quote authenticates itself but is undated, so without a
    # challenge a replayed cached quote is indistinguishable from a new one. Must be
    # random — never a counter or a clock.
    nonce = secrets.token_bytes(16)
    ev = subprocess.run([CLI, "-s", teeUrl, "get-evidence", "--app-id", APP,
                         "--nonce", nonce.hex()],
                        capture_output=True, text=True, timeout=90)
    m = re.search(r'Evidence \(hex\): ([0-9a-f]+)', ev.stdout)
    if not m:
        print(f"  2. FAIL fetching evidence: {(ev.stdout + ev.stderr).strip()[:160]}")
        all_ok = False; continue
    hexstr = m.group(1)
    raw = binascii.unhexlify(hexstr)
    j = json.loads(raw)
    print(f"  2. ok, evidence ({len(raw)} B)")

    # ───────── 3. verify quote signature + TCB (CoCo-AS gRPC 50004) ─────────
    req = {"verification_requests": [
            {"tee": "tdx", "evidence": base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}]}
    open("/tmp/_as_req.json", "w").write(json.dumps(req))
    out = subprocess.run(
        f"grpcurl -plaintext -import-path {os.path.dirname(PROTO)} -proto {PROTO} "
        f"-d @ {AS} attestation.AttestationService/AttestationEvaluate < /tmp/_as_req.json",
        shell=True, capture_output=True, text=True, timeout=90)
    tm = re.search(r'"attestationToken":\s*"([^"]+)"', out.stdout)
    as_status = tcb = as_report_data = None
    if tm:
        pl = tm.group(1).split('.')[1]; pl += '=' * (-len(pl) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pl))
        sm = claims.get("submods", {}).get("cpu0", {})
        as_status = sm.get("ear.status")
        tdx = sm.get("ear.veraison.annotated-evidence", {}).get("tdx", {})
        tcb = tdx.get("tcb_status"); adv = tdx.get("advisory_ids", [])
        qb = (tdx.get("quote", {}) or {}).get("body", {}) or {}
        as_report_data = qb.get("report_data")     # AS aligns this per quote version
        print(f"  3. AS: ear.status={as_status}  tcb_status={tcb}  advisories={len(adv)}")
    else:
        print(f"  3. FAIL, no token from AS: {(out.stdout + out.stderr).strip()[:160]}")

    # ───────── 4. reconcile evidence against the chain ─────────
    # report_data always comes from the AS's parse, never from hand-computed quote offsets:
    # the header length varies with quote version and getting it wrong misreads the field.
    #
    # v0.4.0+: report_data = sha512(runtime_data), runtime_data being a third field of the
    #          evidence. Check that equality FIRST and only then read the fields out of it —
    #          the other order means trusting JSON the quote does not cover.
    # Older:   no runtime_data field, and report_data's first 20 bytes are the signer.
    fresh = tls_pubkey = None
    rd_b64 = j.get("runtime_data")
    if rd_b64:
        rd_bytes = base64.b64decode(rd_b64)        # bytes as received: never loads-then-dumps
        bound = bool(as_report_data) and \
            hashlib.sha512(rd_bytes).digest() == bytes.fromhex(as_report_data.removeprefix("0x"))
        rd = json.loads(rd_bytes)
        sig_ok = bound and rd.get("signer", "").lower() == signer.lower()
        fresh = bound and rd.get("nonce", "").lower() == "0x" + nonce.hex()
        tls_pubkey = rd.get("tls_public_key") if bound else None
        if not bound:
            print("  4. WARNING report_data != sha512(runtime_data): binding does not hold, "
                  "every field in it is untrustworthy")
    else:
        # Old reading: anchor on the on-chain signerAddress as a substring, no fixed offset.
        sig_ok = bool(as_report_data) and signer.lower()[2:] in as_report_data.lower()
        print("  4. note: no runtime_data in evidence, node predates v0.4.0 — verifying the "
              "signer with the old report_data reading")
    # cc_eventlog -> last successful start_app whose compose matches the chain
    log = base64.b64decode(j["cc_eventlog"]); o = 8 + 20
    ds, = struct.unpack_from('<I', log, o); o += 4 + ds
    last = None
    while o + 12 <= len(log):
        pcr, et = struct.unpack_from('<II', log, o); o += 8
        cnt, = struct.unpack_from('<I', log, o); o += 4
        for _ in range(cnt):
            a, = struct.unpack_from('<H', log, o); o += 2 + ALG.get(a, 48)
        dl, = struct.unpack_from('<I', log, o); o += 4
        data = log[o:o+dl]; o += dl
        if et == 0x6 and dl >= 8:
            t = data[8:8 + struct.unpack_from('<I', data, 4)[0]].decode('utf-8', 'replace')
            if t.startswith("tapp.0g.com start_app"):
                d = json.loads(t.split(" ", 2)[2])
                if d.get("app_id") == APP and d.get("compose_hash") == compose_hex and d["result"] == "success":
                    last = d
    if not last:
        print("  4. FAIL: no successful start_app whose compose matches the chain")
        all_ok = False; continue
    ev_vol = b"".join(k.encode() + b":" + bytes.fromhex(v) + b"\n"
                      for k, v in sorted(last["volumes_hash"].items()))
    cmp_ok = last["compose_hash"] == compose_hex
    vol_ok = ev_vol == volumes_bytes
    img_ok = sorted(set(last["image_hash"].values())) == sorted(set(images))
    ok = lambda b: "ok" if b else "FAIL"
    print(f"  4. signer={ok(sig_ok)}  compose={ok(cmp_ok)}  "
          f"volumes={ok(vol_ok)}  image={ok(img_ok)}"
          + ("" if fresh is None else f"  challenge={'echoed' if fresh else 'NOT echoed'}"))
    if tls_pubkey:
        # This is the thread tying "the TEE I verified" to "the endpoint I am talking to":
        # compare it against the sha256 of the public key offered during the handshake.
        # Absent means the app has never asked for a TLS key, which is not a failure.
        print(f"     tls key: {tls_pubkey}  (sha256 of the public key, attested)")
        print( "              compare against the endpoint with:")
        print( "              openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \\")
        print( "                | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \\")
        print( "                | openssl dgst -sha256")

    # A challenge that was not echoed means this quote was not produced for this request,
    # which is as hard a failure as a measurement that does not reconcile.
    node_ok = all([sig_ok, cmp_ok, vol_ok, img_ok]) and fresh is not False
    quote_ok = (as_status == "affirming")
    all_ok &= node_ok
    print(f"  => reconcile {'PASS' if node_ok else 'FAIL'} ; "
          f"quote {'trusted' if quote_ok else f'NOT trusted ({as_status}/{tcb})'}")

print(f"\n### verdict: reconcile {'PASS on every node' if all_ok else 'FAILED on at least one node'}")
