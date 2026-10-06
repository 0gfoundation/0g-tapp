#!/usr/bin/env python3
"""
tapp node verifier. The only input is an app_id; everything else is automatic:
read the chain, fetch evidence, verify the quote at the AS, compare the boot chain with
the published reference values, reconcile the evidence with the chain. The same logic as
`tapp-cli verify-app` (tapp-common/src/verify.rs, refvalues.rs).

Requires: cast (foundry), tapp-cli, grpcurl, and attestation.proto alongside this file.
Usage: python3 verify_app.py <app_id>

Environment overrides: CAST, TAPP_CLI, REGISTRY, RPC_URL, AS_ENDPOINT, REFERENCE_VALUES,
RELAY. Two TappRegistry deployments exist and an app lives on exactly one of them, so
REGISTRY has to name the right one. See contract/CONTRACTS.md.

The AS is relied on for the quote's signature chain, TCB and the event-log replay. The
boot chain is compared HERE against the published reference values
(0gfoundation/0g-tapp@dev:verifier/reference-values, or REFERENCE_VALUES=<dir>).

A node whose port is closed to you is reached through its registry's scan relay (RELAY
overrides it). Transport only: the evidence is checked exactly the same way, and the
quote must echo the random challenge sent for it."""
import sys, os, json, base64, struct, subprocess, re, binascii, hashlib, secrets
import urllib.parse, urllib.request, urllib.error

APP   = sys.argv[1] if len(sys.argv) > 1 else "0g-agentic-id-attestor"
CAST  = os.environ.get("CAST", "cast")
CLI   = os.environ.get("TAPP_CLI", "tapp-cli")
C     = os.environ.get("REGISTRY", "0x2Ce80374318B1d7Fb3345724457a182E0ad165c9")  # TappRegistry (0G testnet)
R     = os.environ.get("RPC_URL", "https://evmrpc-testnet.0g.ai")
# CoCo-AS gRPC, verifies evidence. Same rule as tapp-cli: https:// = TLS, a bare
# host:port = plaintext. The AS serves a self-signed certificate, so the TLS here is
# encryption without authentication (tapp-cli verify-app --as-pubkey pins it).
AS    = os.environ.get("AS_ENDPOINT", "https://35.253.66.70:50004")
RELAYS = {"0x2ce80374318b1d7fb3345724457a182e0ad165c9": "https://tappscan.0g.ai",          # testnet
          "0x54874f536301c993922dd95097e3902e7fbfe612": "https://tappscan.0g.ai/mainnet"}  # mainnet
RELAY = os.environ.get("RELAY", RELAYS.get(C.lower(), "")).rstrip("/")
REFS  = os.environ.get("REFERENCE_VALUES", "")
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

# ───────── 0. reference values: what an audited image measures ─────────
ANY_BSA = "_any_bsa"   # a UKI digest is compared against ANY boot-services application

def parse_set(raw):
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    vals = {}
    for k, v in (d.items() if isinstance(d, dict) else []):
        m = re.fullmatch(r"measurement\.(.+)\.SHA-384", k)
        v = [x for x in (v if isinstance(v, list) else []) if x]
        if m and v:
            vals[ANY_BSA if m.group(1) == "uki" else m.group(1)] = v
    return vals or None

def load_refs():
    sets = {}
    if REFS:
        for root, _, files in os.walk(REFS):
            for f in files:
                if f.endswith(".json"):
                    p = os.path.join(root, f)
                    if (v := parse_set(open(p, "rb").read())):
                        sets[os.path.relpath(p, REFS)] = v
        return sets, REFS
    repo, ref, path = "0gfoundation/0g-tapp", "dev", "verifier/reference-values"
    def get(url, accept):
        req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "verify_app.py"})
        if os.environ.get("GITHUB_TOKEN"):
            req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    commit = get(f"https://api.github.com/repos/{repo}/commits/{ref}", "application/vnd.github.sha").decode().strip()
    cache = os.path.join(os.path.expanduser("~/.cache"), "tapp-cli/reference-values", commit)  # shared with tapp-cli
    if not os.path.isdir(cache):
        tree = json.loads(get(f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1",
                              "application/vnd.github+json"))
        if tree.get("truncated"):
            raise RuntimeError("tree came back truncated")
        tmp = cache + ".tmp"
        for e in tree["tree"]:
            rel = e["path"].removeprefix(path + "/")
            if e["type"] == "blob" and e["path"].startswith(path + "/") and rel.endswith(".json"):
                raw = get(f"https://raw.githubusercontent.com/{repo}/{commit}/{e['path']}", "*/*")
                os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
                open(os.path.join(tmp, rel), "wb").write(raw)
        os.rename(tmp, cache)
    for root, _, files in os.walk(cache):
        for f in files:
            p = os.path.join(root, f)
            if (v := parse_set(open(p, "rb").read())):
                sets[os.path.relpath(p, cache)] = v
    return sets, f"{repo}@{ref} ({commit[:12]}):{path}"

def boot_digests(logs):
    """Same selection rules as tapp-common/src/refvalues.rs and verifier/policy.rego."""
    m = {}
    add = lambda c, d: m.setdefault(c, set()).add(d)
    for e in logs:
        d = next((x.get("digest") for x in e.get("digests", []) if x.get("alg") == "SHA-384"), None)
        if not d:
            continue
        det = e.get("details") or {}
        if e.get("type_name") == "EV_EFI_BOOT_SERVICES_APPLICATION":
            add(ANY_BSA, d)
            paths = " ".join(x for x in det.get("device_paths", []) if isinstance(x, str)).lower()
            if "shimx64.efi" in paths: add("shim", d)
            elif "grubx64.efi" in paths: add("grub", d)
        elif e.get("type_name") == "EV_IPL":
            st = det.get("string") or ""
            if st.startswith("kernel_cmdline:"): add("kernel_cmdline", d)
            elif st.startswith("/vmlinuz"): add("kernel", d)
            elif st.startswith("/initrd"): add("initrd", d)
    return m

def identify(m, sets):
    """(matched label, closest (label, hits, of)) — exhaustive, like tapp-cli."""
    fmt = "grub" if "grub" in m else "uki"
    best = None
    for label, vals in sorted(sets.items()):
        hits = sum(1 for c, allowed in vals.items() if m.get(c, set()) & set(allowed))
        if hits == len(vals):
            return label, None
        same_fmt = ("grub" if ("grub" in vals or "shim" in vals) else "uki") == fmt
        if same_fmt and hits and (best is None or hits > best[1]):
            best = (label, hits, len(vals))
    return None, best

try:
    REF_SETS, ref_src = load_refs()
    print(f"reference values: {ref_src} — {len(REF_SETS)} published image(s)\n")
except Exception as e:
    REF_SETS = None
    print(f"reference values: unavailable ({e}) — the boot chain is NOT checked\n")

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
boot_all = None
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
    raw = relayed = None
    try:
        ev = subprocess.run([CLI, "-s", teeUrl, "get-evidence", "--app-id", APP,
                             "--nonce", nonce.hex()],
                            capture_output=True, text=True, timeout=30)
        m = re.search(r'Evidence \(hex\): ([0-9a-f]+)', ev.stdout)
        direct_err = None if m else (ev.stdout + ev.stderr).strip()[:160]
        raw = binascii.unhexlify(m.group(1)) if m else None
    except subprocess.TimeoutExpired:
        direct_err = "no answer within 30s"
    if raw is None and RELAY:
        # The node's port may be open only to the scan. Transport only: the bytes are
        # checked below exactly as if fetched directly, challenge included.
        url = (f"{RELAY}/api/apps/{urllib.parse.quote(APP, safe='')}/nodes/{signer}/evidence"
               f"?nonce=0x{nonce.hex()}")
        try:
            with urllib.request.urlopen(url, timeout=90) as resp:
                raw = base64.b64decode(json.load(resp)["evidence"])
            relayed = RELAY
        except (urllib.error.URLError, KeyError, ValueError) as e:
            detail = e.read().decode(errors="replace").strip() if isinstance(e, urllib.error.HTTPError) else e
            direct_err = f"{direct_err}; relayed by {RELAY}: {str(detail)[:160]}"
    if raw is None:
        print(f"  2. FAIL fetching evidence: {direct_err}")
        all_ok = False; continue
    j = json.loads(raw)
    print(f"  2. ok, evidence ({len(raw)} B)"
          + (f" — the node did not answer here; relayed by {relayed} (transport only)" if relayed else ""))

    # ───────── 3. verify quote signature + TCB (CoCo-AS gRPC 50004) ─────────
    req = {"verification_requests": [
            {"tee": "tdx", "evidence": base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}]}
    open("/tmp/_as_req.json", "w").write(json.dumps(req))
    out = subprocess.run(
        f"grpcurl {'-insecure' if AS.startswith('https://') else '-plaintext'} "
        f"-import-path {os.path.dirname(PROTO)} -proto {PROTO} "
        f"-d @ {AS.split('://', 1)[-1]} attestation.AttestationService/AttestationEvaluate < /tmp/_as_req.json",
        shell=True, capture_output=True, text=True, timeout=90)
    tm = re.search(r'"attestationToken":\s*"([^"]+)"', out.stdout)
    as_status = tcb = as_report_data = None
    boot = "not checked"; boot_ok = None; replay_ok = False
    if tm:
        pl = tm.group(1).split('.')[1]; pl += '=' * (-len(pl) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pl))
        sm = claims.get("submods", {}).get("cpu0", {})
        as_status = sm.get("ear.status")
        tdx = sm.get("ear.veraison.annotated-evidence", {}).get("tdx", {})
        tcb = tdx.get("tcb_status"); adv = tdx.get("advisory_ids", [])
        qb = (tdx.get("quote", {}) or {}).get("body", {}) or {}
        as_report_data = qb.get("report_data")     # AS aligns this per quote version
        logs = tdx.get("uefi_event_logs") or []
        # Only tapp's own events must replay: a firmware event's digest is of the file it
        # loaded, so the AS's per-event flag is false there on every healthy node.
        replay_ok = not any((e.get("details") or {}).get("data", {}).get("domain") == "tapp.0g.com"
                            and e.get("digest_matches_event") is False for e in logs)
        measured = boot_digests(logs)
        if REF_SETS is not None:
            label, near = identify(measured, REF_SETS)
            boot_ok = label is not None
            boot = (f"ok {label.removesuffix('.json')}" if boot_ok else
                    "FAIL matches no published image"
                    + (f" (closest {near[0].removesuffix('.json')}, {near[1]}/{near[2]})" if near else ""))
        print(f"  3. AS: quote ok  tcb_status={tcb}  advisories={len(adv)}  "
              f"event log {'replays' if replay_ok else 'does NOT replay'}")
        print(f"     boot chain: {boot}")
        if not boot_ok:
            uki = "grub" not in measured
            for c, ds in sorted(measured.items()):
                if c != ANY_BSA or uki:
                    print(f"       measurement.{'uki' if c == ANY_BSA else c}.SHA-384: {sorted(ds)}")
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
    # which is as hard a failure as a measurement that does not reconcile. Through a relay
    # freshness must be PROVEN: replaying an old, genuine quote is what a relay could do.
    # And nothing read from an event log that does not replay can be believed.
    node_ok = all([sig_ok, cmp_ok, vol_ok, img_ok, replay_ok]) and fresh is not False \
        and (fresh is True or not relayed)
    all_ok &= node_ok
    boot_all = boot_ok if boot_all is None else (boot_all and boot_ok if boot_ok is not None else boot_all)
    print(f"  => reconcile {'PASS' if node_ok else 'FAIL'} ; boot chain {boot} ; TCB {tcb}")

print(f"\n### verdict: reconcile {'PASS on every node' if all_ok else 'FAILED on at least one node'}"
      f" ; boot chain {'not checked' if boot_all is None else 'every node runs a published image' if boot_all else 'FAILED'}")
