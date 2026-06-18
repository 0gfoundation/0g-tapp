#!/usr/bin/env python3
"""
tapp 节点验证器 —— 输入只有 app_id，自动走 链上 → 取证 → AS验签 → 对账。
对应文档 docs/EVIDENCE_AND_AS_VERIFICATION.md 的 ①②③④。

依赖: cast (foundry), tapp-cli, grpcurl, 同目录下 attestation.proto
用法: python3 verify_app.py <app_id>
"""
import sys, os, json, base64, struct, subprocess, re, binascii

APP   = sys.argv[1] if len(sys.argv) > 1 else "0g-agentic-id-attestor"
CAST  = os.environ.get("CAST", "cast")
C     = "0x95a0BF4148b30F6F8D86870534c51df46Da5511c"          # TappRegistry (0G testnet)
R     = "https://evmrpc-testnet.0g.ai"
AS    = "47.237.201.184:50004"                                # CoCo-AS gRPC (验 evidence)
PROTO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attestation.proto")
ALG   = {4: 20, 0xb: 32, 0xc: 48, 0xd: 64}
print(f"### 验证 app_id = {APP}\n")

def cast_call(sig, *args):
    out = subprocess.run([CAST, "call", C, sig, *args, "--rpc-url", R],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout.strip()

def split_top(s):                       # 顶层逗号切分(尊重 []())
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

# ───────── ① 链上读注册信息 ─────────
print("## ① 链上")
ai = cast_call("getAppInfo(string)((bytes,bytes,bytes[],address,uint256))", APP)
f = split_top(ai.strip()[1:-1])
compose_hex   = f[0][2:]
volumes_bytes = bytes.fromhex(f[1][2:]) if f[1] != "0x" else b""
images        = [bytes.fromhex(x.strip()[2:]).decode("utf-8", "replace")
                 for x in f[2][1:-1].split(",") if x.strip()]
print(f"  composeHash = {compose_hex}")
print(f"  imageHashes = {sorted(set(images))}")
nodes = re.findall(r"0x[0-9a-fA-F]{40}", cast_call("getNodeList(string)(address[])", APP))
print(f"  nodeList    = {nodes}")
if not nodes:
    print("❌ 链上无该 app，停止。"); sys.exit(1)

all_ok = True
for signer in nodes:
    print(f"\n## 节点 {signer}")
    ni = cast_call("getNode(string,address)((string,uint256,uint256))", APP, signer)
    teeUrl = re.search(r'"([^"]+)"', ni).group(1)
    print(f"  teeUrl = {teeUrl}")

    # ───────── ② 取证 ─────────
    ev = subprocess.run(["tapp-cli", "-s", teeUrl, "get-evidence", "--app-id", APP],
                        capture_output=True, text=True, timeout=90)
    m = re.search(r'Evidence \(hex\): ([0-9a-f]+)', ev.stdout)
    if not m:
        print(f"  ② ❌ 取证失败: {(ev.stdout + ev.stderr).strip()[:160]}"); all_ok = False; continue
    hexstr = m.group(1)
    raw = binascii.unhexlify(hexstr)
    j = json.loads(raw)
    print(f"  ② ✓ evidence ({len(raw)} B)")

    # ───────── ③ AS 验签 (CoCo-AS gRPC 50004) ─────────
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
        as_report_data = qb.get("report_data")               # AS 已按 quote 版本正确对齐
        print(f"  ③ AS: ear.status={as_status}  tcb_status={tcb}  advisories={len(adv)}")
    else:
        print(f"  ③ ❌ AS 无 token: {(out.stdout + out.stderr).strip()[:160]}")

    # ───────── ④ 对账 evidence ↔ 链上 ─────────
    # signer 用 AS 解析出的 report_data（不手搓 quote 偏移——header 长度随 quote version 变, 易错）。
    # report_data 里 signer 恒在偏移 0; 仍以"搜链上 signer 子串"锚定, 不写死偏移。
    sig_ok = bool(as_report_data) and signer.lower()[2:] in as_report_data.lower()
    # cc_eventlog -> 最后一条 compose 匹配的成功 start_app
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
        print("  ④ ❌ 找不到 compose 匹配链上的成功 start_app"); all_ok = False; continue
    ev_vol = b"".join(k.encode() + b":" + bytes.fromhex(v) + b"\n"
                      for k, v in sorted(last["volumes_hash"].items()))
    cmp_ok = last["compose_hash"] == compose_hex
    vol_ok = ev_vol == volumes_bytes
    img_ok = sorted(set(last["image_hash"].values())) == sorted(set(images))
    print(f"  ④ signer={'✅' if sig_ok else '❌'}  compose={'✅' if cmp_ok else '❌'}  "
          f"volumes={'✅' if vol_ok else '❌'}  image={'✅' if img_ok else '❌'}")

    node_ok = all([sig_ok, cmp_ok, vol_ok, img_ok])
    quote_ok = (as_status == "affirming")
    all_ok &= node_ok
    print(f"  → 对账 {'通过 ✅' if node_ok else '不通过 ❌'} ; "
          f"quote {'可信 ✅' if quote_ok else f'不可信 ⚠️ ({as_status}/{tcb})'}")

print(f"\n### 总判定: 对账 {'全部通过 ✅' if all_ok else '有不通过 ❌'}")
