# 按 App ID 验证 tapp 节点（链上 → 取证 → 验签 → 对账）

> **现在已内置到 CLI**：直接用 `tapp-cli verify-app --app-id <X> --rpc-url <RPC> --contract <Registry>`；
> 未注册上链时用直连模式 `tapp-cli -s <server> verify-app --app-id <X>`。本文档描述它内部做的事 +
> 等价的手搓 `cast`/`grpcurl` 流程（`docs/verify_app.py` 是同逻辑的脚本参考；CLI 实现见 `src/verify.rs`）。

**验证器的唯一输入是 `app_id`。** 其余全自动：从链上读该 app 的注册信息和节点列表 →
顺着每个节点链上记录的 `teeUrl` 取 evidence → 验 quote 签名/TCB → 把 evidence 里的度量与身份跟链上逐项对账。

```
输入: app_id
  │
  ├─① 链上 getAppInfo(app_id)        → composeHash / volumesHash / imageHashes / owner
  │   链上 getNodeList(app_id)       → [signerAddress...]  (该 app 的所有节点)
  │   链上 getNode(app_id, signer)   → teeUrl              (每个节点去哪取证)
  │
  └─ 对每个节点 signer:
      ├─② get-evidence(teeUrl, app_id)        取 evidence
      ├─③ 验 quote 签名 + TCB  (CoCo-AS gRPC 47.237.201.184:50004, 见 §③)
      └─④ 对账 evidence ↔ 链上:
            report_data 里的地址 == 该节点 signerAddress
            start_app 事件 compose_hash == 链上 composeHash
            start_app 事件 volumes_hash == 链上 volumesHash
            start_app 事件 image_hash  == 链上 imageHashes
            (+ MRTD/shim/grub/kernel/initrd/cmdline == AS 参考值)
```

链上的信任语义：**「app 该跑 composeHash=C、镜像=I；节点 signer=S 在 teeUrl=U」**。
attestation 证明：**「U 这台 TEE 正在跑 C/I，且其 TEE 派生身份就是 S」** → 信任成立。

合约（0G testnet）：`TappRegistry` proxy `0x95a0BF4148b30F6F8D86870534c51df46Da5511c`，RPC `https://evmrpc-testnet.0g.ai`。

---

## ① 链上读注册信息

合约 getter（`contract/src/TappRegistry.sol`）。`tapp-cli` 只有写链命令，读用 `cast call` / ethers / web3 直接 eth_call：

| getter | 返回 | 字段 |
|---|---|---|
| `getAppInfo(string)` | `AppInfo` | `composeHash`、`volumesHash`、`imageHashes[]`、`owner`、`registeredAt` |
| `getNodeList(string)` | `address[]` | 该 app 所有节点的 **signerAddress** |
| `getNode(string,address)` | `NodeInfo` | `teeUrl`（取证地址）、`addedAt`、`stakeAmount` |

设计上：**app 级**存共享代码身份（compose/volumes/image）；**node 级**按 signerAddress 存各节点 `teeUrl`。

```bash
C=0x95a0BF4148b30F6F8D86870534c51df46Da5511c ; R=https://evmrpc-testnet.0g.ai
cast call "$C" "getAppInfo(string)((bytes,bytes,bytes[],address,uint256))" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNodeList(string)(address[])" "$APP_ID" --rpc-url "$R"
cast call "$C" "getNode(string,address)((string,uint256,uint256))" "$APP_ID" "$SIGNER" --rpc-url "$R"
```

### 链上 hash 的编码（对账时必须按此还原）— `src/onchain.rs:103`

| 字段 | 编码 |
|---|---|
| `composeHash` | 原始 48 字节 SHA-384 |
| `volumesHash` | 排序后每条 `key + ':' + raw(digest) + '\n'` 拼接。digest 是**原始字节**（非 hex 串），**每条带尾 `\n`** |
| `imageHashes[]` | 数组，每个 service 一个 `sha256:<hex>` 的 **ascii** 字节串（无换行）|

> evidence 的 `start_app` 事件里 `volumes_hash` 是 `{"key":"<hexdigest>"}`，对账时要按上面规则重建成
> `key:` + `bytes.fromhex(hexdigest)` + `\n` 再跟链上 `volumesHash` 比对。

---

## ② 取 Evidence（用链上的 teeUrl）

```bash
tapp-cli -s <teeUrl> get-evidence --app-id <APP_ID> 2>&1 \
  | grep -o 'Evidence (hex): [0-9a-f]*' | sed 's/Evidence (hex): //' > ev.hex
```

- `report_data` 由服务端自动填为该 app 的 **TEE 派生 signer EVM 地址**。
- signer 不持久化：tapp server 重启会重新派生、地址变；链上要用 `update-node-onchain` 同步。

---

## ③ 验 quote 签名 + TCB（CoCo-AS gRPC `50004`）

trustee 的 docker-compose 起三个服务：**KBS `8080`**、**AS（coco-as-grpc）`50004`**、RVPS `50003`。
**验 evidence 的正主是 AS 的 `50004`，不是 KBS 的 `8080`。**（KBS 的 `/kbs/v0/attest` 是 RCAR 密钥分发，
要求 `report_data==hash(nonce,pubkey)`，对 signer 绑定的 evidence 一律 401，**不要用它验签**。）

AS 服务：`attestation.AttestationService/AttestationEvaluate`（proto 见 trustee `protos/attestation.proto`）。
请求里 `runtime_data` **留空** → 不做 nonce 绑定，只验 quote 签名链(PCK→Intel 根)+TCB，并把 report_data 解析进 claims。
`evidence` = `base64url(no-pad)` 的**原始 evidence 字节**（即 hex 解码后的 `{cc_eventlog,quote,...}`）。

```python
import binascii, base64, json, subprocess
raw = binascii.unhexlify(open('ev.hex').read().strip())
req = {"verification_requests": [
        {"tee": "tdx", "evidence": base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}]}
open('/tmp/as_req.json','w').write(json.dumps(req))
# 需要 trustee 的 protos/attestation.proto 在本地
subprocess.run(
  "grpcurl -plaintext -import-path . -proto attestation.proto -d @ "
  "47.237.201.184:50004 attestation.AttestationService/AttestationEvaluate < /tmp/as_req.json",
  shell=True)
```

返回 `attestation_token`（JWT / EAR 格式）。解开 payload 看 `submods.cpu0`：

| claim | 含义 |
|---|---|
| `ear.status` | 总判定：`affirming` 通过 / `warning` / `contraindicated` 不通过 |
| `ear.trustworthiness-vector` | 各维度分值：`2`=affirming，`32–95`=warning，`≥96`=contraindicated |
| `tdx.tcb_status` | `UpToDate` / `OutOfDate` / … |
| `tdx.advisory_ids` | 命中的 Intel 安全公告（`INTEL-SA-xxxxx`）|
| `tdx.quote.report_data` / `mr_td` / `rtmr_*` | AS 解析出的度量，可直接用于 §④ 对账 |

> 判定要点：`ear.status == affirming` 才算 quote 可信。`OutOfDate` TCB 会导致 `hardware` 维度
> ≥96 → `contraindicated`（quote 是真的，但平台固件/微码过期，需升级 TCB）。

---

## ④ 解析 evidence + 对账

evidence(hex) 解码后 = `{ cc_eventlog: <base64>, gpu_evidence: null, quote: <base64> }`。

### Quote 度量 / report_data —— 直接取自 §③ 的 AS 解析结果

**不要手搓 quote 字节偏移取度量。** TD body 的字段内部偏移是固定的，但 **body 在 quote 里的起始偏移随 quote version 变**：
v4 header = 48 字节、**v5 header = 54 字节**。硬编 `q[48:]` 在 v5 quote 上会整体错位 6 字节，把 RTMR3 末尾误当成 report_data 前缀——这是个真实踩过的坑（见 `VERIFIER_AGENT_GUIDANCE.md`）。

AS（§③）已按版本正确对齐并解析好，直接读 token 的 `submods.cpu0.ear.veraison.annotated-evidence.tdx.quote.body`：

```python
qb = claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]
report_data = qb["report_data"]   # signer 恒在偏移 0 (前 20 字节), 其余补零
mrtd        = qb["mr_td"]
rtmr3       = qb["rtmr_3"]
```

| 字段 | 含义 |
|---|---|
| MRTD (`mr_td`) | TD 初始内存度量（固件/虚机镜像）；同款镜像多台相同 |
| RTMR0/1/2 | 固件配置 / 引导(shim·grub) / OS(grub 命令·内核·initrd) |
| RTMR3 | 运行时：cryptpilot FDE（老镜像）+ tapp 操作 |
| `report_data` | signer EVM 地址在**偏移 0**（前 20 字节），其余补零。**RTMR(非 report_data)绝不能当 signer** |

> 取 signer 的稳妥做法：从 AS 的 `report_data` 里取前 20 字节，并把链上 `signerAddress`（20字节）当作**子串去搜索/比对**——既不写死 quote 偏移，也以链上值为锚。
> （非要离线手搓时，必须按 `quote[0:2]` 的 version 决定 header 长度：v4→48、v5→54，再 `body[520:584]` 取 report_data。）

### cc_eventlog（TCG2，全程 SHA-384）

```python
log = base64.b64decode(j['cc_eventlog']); ALG = {4:20, 0xb:32, 0xc:48, 0xd:64}
o = 0; o += 8; o += 20; ds, = struct.unpack_from('<I', log, o); o += 4 + ds   # 跳过 SpecID
while o + 12 <= len(log):
    pcr, et = struct.unpack_from('<II', log, o); o += 8
    cnt,    = struct.unpack_from('<I', log, o);  o += 4
    d384 = None
    for _ in range(cnt):
        alg, = struct.unpack_from('<H', log, o); o += 2
        if alg == 0xc: d384 = log[o:o+ALG[alg]].hex()
        o += ALG.get(alg, 48)
    dl, = struct.unpack_from('<I', log, o); o += 4; data = log[o:o+dl]; o += dl
    if et == 0x6 and dl >= 8:                                  # EV_EVENT_TAG: 前8字节是tag头
        text = data[8:8 + struct.unpack_from('<I', data, 4)[0]].decode('utf-8','replace')
        # text = "<domain> <operation/key> <value>"
```

### 度量匹配规则（对 AS 参考值）

| 字段 | 匹配方式 | 备注 |
|---|---|---|
| MRTD / shim / grub / kernel | 精确 | 同镜像相同 |
| initrd | 精确 | **每台可能不同**，各匹配各自参考值 |
| kernel_cmdline | **OR** | 见下 |
| report_data 内地址 | = 链上 signerAddress | 见上 |
| compose / volumes / image hash | = 链上对应字段 | 见 §① 编码规则 |

**kernel_cmdline 有两条参考值（新/旧 grub），命中其一即通过：**

| | 内核路径写法 | 实例 digest |
|---|---|---|
| 新 grub | `/vmlinuz-<ver> root=… ip=dhcp`（相对 `$root`）| `7dd3d3d1…` |
| 旧 grub | `(hd0,gptN)/boot/vmlinuz-<ver> root=… …`（grub 设备全路径）| `bad43ebbd…`（GCP 6.17 内核例）|

两者内核与参数完全相同，差别仅是内核路径文字表示 → 哈希不同。
digest = `SHA384(cmdline字符串)`（去掉 eventlog 里 `kernel_cmdline: ` 前缀、不含结尾 null）。
> 实测：GCP 镜像（新 grub）只产生 `/vmlinuz` 形式；老阿里云镜像（旧 grub）产生 `(hd0,gpt3)/boot/vmlinuz` 形式。

---

## RTMR3 运行时事件（对账数据来源）

RTMR3 的 `EV_EVENT_TAG` 是运行时度量，统一格式 `<domain> <key/operation> <value>`，按 domain 分两类：

### cryptpilot（老阿里云镜像，全盘加密 FDE）

domain `cryptpilot.alibabacloud.com`，initrd 阶段产生，排在 tapp 事件之前。
**仅用 cryptpilot 的老镜像有**；新 GCP 镜像没有这几条。

| key | value | 含义 |
|---|---|---|
| `load_config` | `<SHA-384>` | cryptpilot 配置度量 |
| `fde_rootfs_hash` | `<hash>` | 全盘加密 rootfs 哈希 |
| `initrd_switch_root` | `{}` | initrd 切根标记 |

### tapp 操作

domain `tapp.0g.com`，由 `start_app`/`stop_app`/`start_service`/`get_app_secret_key`/`docker_login` 触发
（代码 `extend_measurement()` → AA `extend_runtime_measurement`）：

```
tapp.0g.com <operation> {"app_id","operation","result","error",
  "compose_hash","volumes_hash","image_hash","deployer","timestamp"}
```

- 对账取**最后一条 `result:"success"` 且 `compose_hash` == 链上 composeHash 的 `start_app`**。
- 成功和失败都记录（失败：`result:"failed"` + error 文本 + `image_hash:{}` 空）。
- `docker_login` 记 `registry/username/signer/timestamp`（不含密码）。
- 规律：每次会话第一条运行时事件落 `pcrIndex=1`，之后落 `pcrIndex=4`。

### claim_config（运行时认领 owner+配置,canonical 镜像必查）

canonical 镜像不烧 owner/chain/kbs(黄金参考值全网一套,路径 `<env>.json` 无 owner 层),
**整个运行时配置从静态度量搬进了运行时事件日志**:

```
tapp.0g.com claim_config {"owner":"0x<owner>","chain_rpc_url":"…",
  "chain_contract_address":"0x…","kbs_node_urls":["…"],
  "operation":"claim_config","timestamp":<ts>}
```

对账规则(在 §④ 增加一步):

1. 事件日志里**必须存在 `claim_config` 事件**(无 → 节点无主或走了度量外路径,拒绝);
2. 若有多条(如 config 模式跨进程重启),**所有 `claim_config` 的 `owner` 必须一致**;
3. `owner` == 链上该节点注册的 owner(不一致 → owner 被抢注或注册不符,拒绝);
4. `chain_contract_address` / `kbs_node_urls` 供审计:节点当时认领的是哪个合约、哪个 KMS 集群。

claim 事件由启动后的首次认领产生(ClaimConfig RPC 的动态模式,或 config.toml 预制模式启动自动认领),
每次 VM 重启 RTMR 清零、重新认领、重新度量——owner 与 quote 始终同生命周期。

---

## 实测走查：`0g-agentic-id-attestor`（严格照本文档端到端跑过）

输入 `app_id = 0g-agentic-id-attestor`，全自动（脚本见 §附）：

```
① 链上:
   getAppInfo  → composeHash 740e9c57…2751d8 / volumesHash .env:<digest>\n / imageHashes[sha256:b7aaa6…, sha256:4b7183ac…]
   getNodeList → [0x6C30D1E9392eaF67DAB66c4962249DE821CD335f]
   getNode     → teeUrl http://47.84.230.10:50051   stake 1 0G
② 取证: get-evidence @ 47.84.230.10  (老阿里云镜像: MRTD 060000…, cryptpilot FDE, 旧 grub)   ✅
③ AS 验签 @ 47.237.201.184:50004 (AttestationEvaluate): 返回 token, quote 签名✅, report_data 解出=0x6C30…335f
        但 tcb_status=OutOfDate (INTEL-SA-01036 等 8 条) → ear.status=contraindicated  ⚠️ 平台 TCB 过期
④ 对账:
   node signer  0x6C30…335f      == AS report_data 前20字节            ✅
   composeHash  740e9c57…2751d8   == start_app(ts 1781099341).compose ✅
   volumesHash  .env:<digest>\n   == start_app.volumes_hash (重建)    ✅
   imageHashes  sha256:b7aaa6…/4b7183ac… == start_app.image_hash       ✅
```

**节点判定**：身份 + 代码度量对账**全部通过**（①②④）；AS 验签**接口可用、quote 真实**，但该节点
**TCB 过期**导致 `contraindicated`（③）——属真实安全发现（需升级平台固件/微码），非验证失败。
①②③④ 均已端到端实测跑通。

---

## 速查 checklist（输入 = app_id）

1. 链上 `getAppInfo` / `getNodeList` / `getNode` 读注册信息 + 各节点 teeUrl。
2. 对每个节点：按 teeUrl `get-evidence --app-id <id>`。
3. 验 quote 签名 + TCB：提交 **CoCo-AS gRPC `47.237.201.184:50004`** `AttestationEvaluate`（`runtime_data` 留空），看 `ear.status==affirming` 且 `tcb_status==UpToDate`（**别用 8080 KBS，那是 RCAR 密钥分发，会 401**）。
4. 对账：取 AS 解析的 report_data 前20字节==signerAddress（别手搓 quote 偏移）；compose/volumes/image hash==链上（按 §① 编码）；MRTD/启动链==AS 参考值（cmdline OR）。
5. RTMR3 识别 cryptpilot（老镜像）+ 取最后一条成功 start_app 做 compose/image/volumes 对账。
