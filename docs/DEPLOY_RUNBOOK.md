# App Deployment Runbook (tapp + TappRegistry)

把一个 app（以 sandbox **provider** + **broker** 为例）从零部署到 tapp、并在 TappRegistry 上链可用的标准流程与踩坑清单。

- **合约**：TappRegistry BeaconProxy `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9`
- **RPC / chainId**：`https://evmrpc-testnet.0g.ai` / `16602`
- **compose**：provider → `0g-sandbox/docker/sandbox/docker-compose.yml`，broker → `0g-sandbox/docker/broker/docker-compose.yml`

> 详细的合约用法见 [`contract/CONTRACTS.md`](../contract/CONTRACTS.md)，tapp-cli 用法见 [`.claude/skills/0g-tapp-cli/SKILL.md`](../.claude/skills/0g-tapp-cli/SKILL.md)。

---

## 标准步骤

| # | 步骤 | 命令 / 要点 | provider | broker |
|---|------|------------|:---:|:---:|
| 1 | 配 tapp-server config 的 owner，起 tapp 服务器 | 该 owner key 之后用于所有 start/stop/register | ✅ | ✅ |
| 2 | `start-app` 起服务 | `PROVIDER_ADDRESS` 必须 == 该 app 的链上 owner；先 `docker-login` 私有 registry；`.env` 的 `TAPP_REGISTRY`/`SETTLEMENT_CONTRACT` 要齐 | ✅ | ✅ |
| 3 | `register-onchain` 注册上链 | 各质押 1 0G | ✅ | ✅ |

> 步骤 2+3 可合并为一条：`start-app --register-onchain --rpc-url … --contract … --stake-wei …`
> 会在容器启动**之前**幂等注册（未注册→registerApp；已注册但本节点 signer 不在 node list→addNode；已在→跳过）。
> server 先 pull 镜像算好 hash，交易确认后才 up；重启后 signer 变的场景会自动走 addNode（旧 node 仍需手动 remove/update）。
| 4 | `authorizeInvalidator(appId, <SandboxServing 合约地址>)` | 授权兄弟合约 SandboxServing 调 `invalidateAcks`，使改价能作废用户 ack；**必须在第 5 步前** | ✅ | — |
| 5 | `cmd/provider register` 绑服务到 SandboxServing | 设 `services[provider].appId` + 价格 | ✅ | — |

```bash
# 2. 起服务（先 docker-login）
tapp-cli -s http://<server>:50051 -k 0x<owner-key> docker-login -r <registry> -u <user> -p <pass>
tapp-cli -s http://<server>:50051 -k 0x<owner-key> start-app -f <compose> --app-id <appId>

# 3. 注册上链（key 必须既是 server owner 又是有钱的 app owner）
tapp-cli -s http://<server>:50051 -k 0x<owner-key> register-onchain \
  --app-id <appId> --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 --stake-wei 1000000000000000000

# 2+3 合并版：先注册再起（幂等，可反复跑）
tapp-cli -s http://<server>:50051 -k 0x<owner-key> start-app -f <compose> --app-id <appId> \
  --register-onchain --rpc-url https://evmrpc-testnet.0g.ai \
  --contract 0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 --stake-wei 1000000000000000000

# 4. 授权 invalidator（注意：授权的是 SandboxServing 合约地址，不是 owner 钱包）
#    暂无 tapp-cli 子命令，直接 cast send（注意 gas）
cast send 0x2Ce80374318B1d7Fb3345724457a182E0ad165c9 \
  "authorizeInvalidator(string,address)" "<appId>" 0x<SANDBOX_SERVING_CONTRACT> \
  --rpc-url https://evmrpc-testnet.0g.ai --private-key 0x<owner-key> \
  --legacy --gas-price 3000000000

# 5. provider 注册服务（在 0g-sandbox repo）
PROVIDER_KEY=0x<owner-key> go run ./cmd/provider register --app-id <appId> --url ... --price-per-cpu ...
```

> broker 只到第 3 步；步骤 4、5 是 provider 专属。

---

## 踩坑清单（最容易再犯）

- **三 key 合一**：`register-onchain` 的 `--private-key` 必须**同时**满足「能连 server（server owner 或白名单）」+「是 app 将来的 owner」+「链上有钱（质押 1 0G + gas）」。三者必须同一地址——最常卡这。
- **invalidator 授给合约，不是钱包**：`invalidateAcks` 判 `msg.sender == SandboxServing 合约`。授权 owner EOA 会让 `isAuthorizedInvalidator` 返回 true，但合约调用仍 revert `sandbox not authorized as invalidator`。
- **`PROVIDER_ADDRESS` 必须 == app 链上 owner**，否则 sandbox 的 signer_mismatch monitor 报不一致、voucher 全 `INVALID_SIGNATURE`。
- **重启 → TEE signer 变**：TEE 派生 signer 不持久化，任何 `stop/start` 后链上 node 过期 → 补 `update-node-onchain`（`--old-signer` 传旧的，新 signer 自动从 server 取）。
- **换 owner 无 transfer**：owner 在 `registerApp` 写死。换 owner = 旧 owner `removeNode` 注销（质押锁 `lockPeriod`=86400s/1 天，到期旧 owner 自己 `withdraw()`）→ 新 owner 重新 `register`。
- **app-id 全局唯一**：register 撞名报 `app already exists`。已存在只能 `add-node` / `update-node`（`update-node` 会替掉原 node，注意别误删别处生产 node）。
- **service appId set-once**：改 appId 报 `appId immutable; deregister to change`，要先 deregister。
- **`cast send` gas 太低被拒**：默认 tip 1 wei < 最低 2 gwei，手动加 `--legacy --gas-price 3000000000`。tapp-cli 的 onchain 子命令自己处理 gas，无需此参。
- **私有 registry 临时 token 寿命短**：docker-login 后很快过期，拉镜像 `unauthorized` 就重新登录。
- **部分云主机 docker 无 DNS**：解析不了 `docker.io`，公共镜像拉不下来，需在主机配 docker DNS（`/etc/docker/daemon.json` 的 `"dns"`）。

---

## imageHashes 全空的根因（已修，存档）

**现象**：链上 `getAppInfo(appId).imageHashes` 为空数组 `[]`，且 `tapp-cli get-app-info` 显示 `Image Hash: {}`（compose/volume hash 正常）。

**根因**：tapp-server 通过 `docker compose images --format json` 枚举镜像。某些主机该命令输出**单行 JSON 数组** `[{...},{...}]`，而**旧 tapp-server 二进制按 NDJSON 逐行解析** → `invalid type: map, expected a string` → 整行 skip → `image_count=0` → image_hash `{}`。

**修复**：`prune`/重拉/重新注册都治不了，必须换二进制。当前源码 `src/boot/manager.rs` 已改为 `serde_json::from_str::<Vec<ImageInfo>>(stdout.trim())` 整体数组解析。换上当前 build 的 tapp-server + 重启 app + `update-onchain` 后 imageHashes 即非空。
