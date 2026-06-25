# GCP TApp 机密镜像（CVM）构建包

从裸 Ubuntu 24.04 cloud 镜像构建可启动、可度量、可远程证明、且已安全加固的 cryptpilot TApp 机密镜像。

## 目录内容
| 文件 | 说明 |
|---|---|
| `cryptpilot-gcp-boot-fix.md` | **主文档**：根因分析 + 修复 + 完整 SOP（§9）+ 安全加固审计（§11）+ 给阿里云的 convert 问题（§7） |
| `build-gcp-tapp.sh` | **一键全链**：裸镜像 → 最终 gcp-tapp（段A 装 app/docker/SGX/DNS+加固 / 段B 内核+convert+ESP） |
| `prepare-gcp-tapp.sh` | 仅段B（已有 base 时）：修复A + DNS(guestfish) + nbd 重置 + convert + 修复B |
| `fix-esp-grub.sh` | 仅同步 ESP grub（修复 B，可单独对已转换镜像跑） |
| `config_dir/` | cryptpilot convert 配置（`fde.toml`，`rw_overlay="ram"`） |
| `cryptpilot-fde_0.7.0_amd64.deb` | FDE 包（提供 cryptpilot-convert + 运行时）。**二进制，已 gitignore 不入库**，需本地放在本目录 |

> 产物 `gcp-tapp.qcow2`（约 6G，已 convert/verity 密封/加固）是 `build-gcp-tapp.sh` 的**输出**，不纳入版本库（已 gitignore）。
> `cryptpilot-fde_*.deb` 与 tapp-server 二进制同理：deb 需本地放在本目录；tapp-server 默认从 GitHub release v0.1.0 拉取（见下）。

## 一键构建
```bash
export LIBGUESTFS_BACKEND=direct
./build-gcp-tapp.sh <裸ubuntu-24.04.qcow2> gcp-tapp.qcow2
```
- tapp-server 默认下 GitHub v0.1.0（含 guest-components `8d71a3b4` 修复，RTMR OK）；本地有则 `TAPP_SERVER_BIN=<路径>`。
- 其它环境变量：`DNS_FALLBACK` `PURGE_KERNEL` `CONFIG_DIR` `FDE_PACKAGE` `ROOTFS_MODE` `IN_PLACE` `INSTALL_KERNEL` `NBD_RESET`（详见脚本顶部）。

## 三个核心修复（缺一不可）
- **修复 A**：convert 前 `/boot/vmlinuz` 软链指向 gcp 内核 → cryptpilot 栈进对的 initrd（修只读/RTMR/verity）。
- **修复 B**：convert 后同步 boot 分区 grub.cfg+模块到 ESP（修启动崩溃 bli.mod/vmlinuz not found）。
- **应用侧（§8）**：tapp-server 用 guest-components `8d71a3b4`（v0.1.0 已含）→ RTMR extend 不再误判。
- 另：DNS 须用 **guestfish** 写静态 `/etc/resolv.conf`（virt-customize 会清掉自己写的）；convert 前 nbd 重置 `modprobe nbd max_part=16`。

## 安全加固（已集成在 build 段A，详见文档 §11）
purge：openssh-server / cloud-init / snapd / google-guest-agent / google-compute-engine(+oslogin) / google-osconfig-agent / google-cloud-ops-agent / open-vm-tools / unattended-upgrades / pollinate / landscape-common；mask 串口/本地 getty；netplan 换 MAC 无关 DHCP。

## 验证（已通过）
- 镜像静态：上述包全 gone、getty masked、netplan=01-dhcp、resolv.conf 3 行、gcp initrd cryptpilot=16。
- 运行时（真 TDX）：SSH 连不上；app 经 tapp 正常启动 + 度量 + RA。
- 内部监听面权威核验：实例内 `ss -tlnp`（锁死后无登录入口，可用开机审计服务输出到串口 console，见文档 §同名建议）。

## 提取参考值（远程证明用）
构建后用含修复（openanolis/cryptpilot#128）的 `cryptpilot-fde` 从镜像离线提取 RA 参考值：
```bash
cryptpilot-fde show-reference-value --disk gcp-tapp.qcow2 --hash-algo sha384
```
原版会因新镜像 grubenv 空报 `saved_entry not found`；详见主文档 **§12**（含从 fork 分支构建带修复的 cryptpilot-fde 的步骤）。

## 待办（可选，"零残留"收尾，不阻塞）
- 删残留 `authorized_keys`（root + 4 真人账号）+ 锁/删真人账号；
- 清 Tier3：`rpcbind`(监听 111)/`lxd-installer.socket` 等。
