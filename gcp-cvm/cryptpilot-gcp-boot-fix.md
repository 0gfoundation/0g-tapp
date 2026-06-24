# cryptpilot-convert 在 GCP Ubuntu 镜像上换内核后启动崩溃 —— 根因分析与修复

> 目的：为在 GCP Ubuntu 镜像上启用 **RTMR extend** 而更换内核（generic → gcp）。过程中遇到四类问题并已全部解决、RTMR extend 在真 TDX 上确认成功：
> 1. **镜像启动崩溃**（grub 找不到内核/模块）——根因 GCP 双 grub.cfg，见 §4/§5 修复 B；
> 2. **rootfs 只读 / RTMR 未 extend / verity 被绕过**——根因 convert 把 cryptpilot 栈装进了错误内核的 initrd，见 §7.3/§5 修复 A；
> 3. **运行时 RTMR 扩展失败**（"Cannot extend runtime measurement"）——根因应用侧 guest-components 探测误判，见 §8；
> 4. **实例 DNS 不通**（需手动 `echo nameserver … > /etc/resolv.conf`）——根因 virt-customize 收尾清理 resolv.conf、resolved 兜底失效，须用 guestfish 写静态 resolv.conf，见 §9。
>
> §1–§7 镜像构建侧（含请 cryptpilot 维护方确认的 convert 问题），§8 应用侧（guest-components）修复，**§9 完整可复现 build 流程（SOP）**，§10 脚本附录。

---

## 1. 环境

| 项 | 值 |
|---|---|
| 基础镜像 | GCP Ubuntu 24.04 cloud image |
| 磁盘布局 | `sda1`=rootfs(ext4), `sda14`=bios-grub, `sda15`=**ESP/EFI**(vfat), `sda16`=**/boot**(ext4) |
| 原内核 | `6.8.0-106-generic` |
| 目标内核 | `linux-image-gcp` → 实际为 `6.17.0-1018-gcp` |
| 转换工具 | `cryptpilot-convert`，由 **cryptpilot-fde 0.7.0** 提供（转换主机上为 `cryptpilot-fde-0.7.0-1.al8`，装入目标镜像的为 `cryptpilot-fde_0.7.0_amd64.deb`） |
| attestation-agent | 目标镜像内实际版本**待确认**（用于 `ExtendRuntimeMeasurement`） |
| 转换参数 | `--rootfs-no-encryption`（仅 measuring，不加密） |

## 2. 原始诉求：为什么要换内核

cryptpilot 通过 attestation-agent(AA) 的 `ExtendRuntimeMeasurement` 接口 extend RTMR；AA 的 TDX attester 走两条路之一：

1. ioctl：`/dev/tdx_guest` 的 `TDX_CMD_EXTEND_RTMR`
2. sysfs（降级）：`/sys/devices/virtual/misc/tdx_guest/measurements/rtmr{N}:sha384`

而原 generic 内核 `6.8.0-106` 的 `tdx_guest` uapi（`/usr/src/linux-headers-*/include/uapi/linux/tdx-guest.h`）**只定义了 `TDX_CMD_GET_REPORT0`**，既无 extend ioctl，也无上述 sysfs measurement 接口 → **无法 extend RTMR**。

- extend ioctl(`TDX_CMD_EXTEND_RTMR`) 是 Intel/Anolis out-of-tree 补丁，未进 Linux 主线；
- sysfs measurement 接口随主线 TSM measurement register 框架引入（约 6.14 起）。

实测确认目标内核 `6.17.0-1018-gcp` 的内核配置含 `CONFIG_TSM_MEASUREMENTS=y`、`CONFIG_TSM_GUEST=y`、`CONFIG_TSM_REPORTS=y`、`CONFIG_INTEL_TDX_GUEST=y`、`CONFIG_TDX_GUEST_DRIVER=m`，具备 sysfs RTMR extend 接口的前提。因此换到该内核以获得 extend 能力，方向正确。

> 注意：换内核只解决了"内核侧接口缺失"。最终在真 TDX 上 RTMR 仍一度失败，根因在**应用侧 guest-components 的探测误判**（见 §8）。须**镜像侧（§5 修复 A/B）+ 应用侧（§8）两处都修**，RTMR extend 才成功。

## 3. 故障现象

换内核后的镜像启动报：

```
error: file '/EFI/ubuntu/x86_64-efi/bli.mod' not found.
error: file '/vmlinuz-6.8.0-106-generic' not found.
error: you need to load the kernel first.
Failed to boot both default and fallback entries.
```

注意 `vmlinuz-6.8.0-106-generic` 是**已被 purge 的旧内核**。

## 4. 根因

GCP Ubuntu 镜像存在**两份 grub.cfg**：

| 文件 | 位置 | 谁更新 | grub 启动时是否读取 |
|---|---|---|---|
| `/boot/grub/grub.cfg` | boot 分区 sda16 | `update-grub` / `cryptpilot-convert` | 否 |
| `/EFI/ubuntu/grub.cfg` | **ESP 分区 sda15** | 仅 `grub-install`（一般构建期一次性生成）| **是（grubx64.efi 的 prefix=`/EFI/ubuntu`）** |

- `update-grub`（以及 `cryptpilot-convert` 内部调用的 update-grub）**只写 `/boot/grub/grub.cfg`**，不更新 ESP 上那份；
- 换内核 + purge 旧内核后，ESP 上的 grub.cfg 仍指向被删的 `6.8.0-106-generic` → `vmlinuz not found`；
- ESP 上没有 `x86_64-efi/` 模块目录（`insmod bli` 来自 `/etc/grub.d/25_bli`）→ `bli.mod not found`（此条非致命，但说明 ESP 的 grub 环境不完整）。

**与 cryptpilot 无直接关系，是 GCP 镜像 grub 布局 + update-grub 行为导致**；但 cryptpilot-convert 内部同样调用 update-grub，故转换后仍会复现该问题。

## 5. 修复方案（已端到端验证）

需要**两个独立修复点，缺一不可**：

**修复 A —— convert 前把 `/boot/vmlinuz` 软链指向 gcp 内核**（解决只读 / RTMR 未 extend / verity 被绕过，详见 §7.3）：
GCP 镜像上装 `linux-image-gcp` 后，`/boot/vmlinuz` 仍指向 generic 内核；convert 按此软链选内核做 `dracut --add cryptpilot`，导致 cryptpilot 栈被装进 generic 的 initrd，而 grub 默认启动的 gcp 内核 initrd 里没有 cryptpilot。把软链改指 gcp 即可让 convert 给正确内核建 initrd。

**修复 B —— convert 后把 boot 分区 grub.cfg + 模块同步到 ESP**（解决启动崩溃，详见 §4）：
```
cp    /boot/grub/grub.cfg   /EFI/ubuntu/grub.cfg          # 同步最新配置
cp -a /boot/grub/x86_64-efi /EFI/ubuntu/x86_64-efi        # 同步 grub 模块(修 bli.mod)
```

完整流程：
```bash
# 1) 换内核 + 把默认内核软链指向 gcp（修复 A：最后一行 ln 是关键）
virt-customize -a gcp-base.qcow2 \
  --install linux-image-gcp,linux-modules-extra-gcp \
  --run-command 'apt-get autoremove --purge linux-image-6.8.0-106-generic -y || true' \
  --run-command 'update-grub' \
  --run-command 'k=$(ls /boot/vmlinuz-*-gcp | sort -V | tail -1 | sed "s#/boot/##"); ln -sf "$k" /boot/vmlinuz; ln -sf "initrd.img-${k#vmlinuz-}" /boot/initrd.img'

# 2) convert（注意 TMPDIR，见 §7.4）
TMPDIR=/tmp cryptpilot-convert --in gcp-base.qcow2 --out gcp-tapp.qcow2 \
  --config-dir ./config_dir/ --rootfs-no-encryption \
  --package cryptpilot-fde_0.7.0_amd64.deb

# 3) 同步 ESP（修复 B，必须在 convert 之后；convert 内部也只更新 boot 分区那份）
./fix-esp-grub.sh gcp-tapp.qcow2
```

> 顺序约束：若需计算参考值 `cryptpilot-fde show-reference-value`，必须在第 3 步**之后**执行（见 §6）。

**验证（QEMU 软件模拟，KVM=N）**：
- 仅做修复 B（未做 A）：grub 能引导 6.17-gcp，但 `cryptpilot-fde-before-sysroot.service` 不在 gcp initrd 里→不运行→rootfs 只读、满屏 `Read-only file system`、cloud-init/docker/snapd 全失败，且 verity/RTMR 均未生效。
- A+B 都做：`cryptpilot-fde-before-sysroot` 正常运行（激活 LVM→加载 root-hash→建 dm-verity→建 zram+dm-snapshot 可写层），`Read-only` 错误归零，启动到 login。
- RTMR extend：镜像侧 A+B 消除了 initrd 缺 cryptpilot 栈的拦路；真 TDX 上最终成功还需应用侧修复（§8 的 guest-components 更新）。两侧齐备后已确认 extend 成功。

## 6. 对镜像完整性 / 测量的影响

| 层面 | 影响 | 说明 |
|---|---|---|
| rootfs dm-verity / `root_hash` | **不受影响** | ESP 与 /boot 不在 verity 保护范围；脚本不碰 verity 数据与 hash 树，initrd 内嵌的 root_hash 不变 |
| qcow2 / 文件系统结构 | **不损坏** | 经 guestfish 规范挂载/卸载，仅向 vfat ESP 写文件 |
| 启动 RTMR 测量值 | **会变（预期）** | grub 会把 kernel/initrd/cmdline 测进 RTMR；同步 ESP 改了 grub.cfg（cmdline 含 `rd.neednet=1 ip=dhcp`）→ 测量值随之变化 |

**结论**：不破坏 rootfs 完整性，也不损坏镜像；只改变启动测量值。只要**先做第 3 步、再算参考值**，即可保证"参考值 == 实际启动测量"。反之若不做第 3 步，ESP 配置过期，要么启动崩溃，要么实际启动与参考值不一致导致远程证明失败。

## 7. 请 cryptpilot 维护方确认的问题

以下为在 Ubuntu/GCP 镜像上使用 `cryptpilot-convert` 时观察到的 convert 侧问题，建议确认是否应在 convert 内修复，使其原生支持该场景：

**7.1 convert 未同步 ESP 上的 grub.cfg（核心）**
convert 内部调用 `update-grub` 仅更新 `/boot/grub/grub.cfg`，未同步 GCP 镜像 ESP 上的 `/EFI/ubuntu/grub.cfg`。建议 convert 在更新 grub 后，检测并同步 ESP 副本（或确保走 UKI 模式绕过 grub）。

**7.2 内核版本探测写死 `-generic`**
（`cryptpilot-convert` 中 zram 模块安装段，约 line 448）
```bash
kernel_version=$(chroot ... "dpkg -l | grep -oP 'linux-image-\K[0-9.-]+-generic' | head -n1")
if [ -z "$kernel_version" ]; then ... return 1; fi
```
该正则只匹配 `-generic` 内核，遇 `-gcp`（或其他 flavor）会抓到残留 generic 或返回空而中止。建议改为探测实际默认内核 flavor。

**7.3 【核心 bug】dracut 目标内核与 grub 默认启动内核不一致 → cryptpilot 栈装错内核**
（约 line 1069–1081）convert 经 `/boot/vmlinuz` 软链选内核执行 `dracut --add cryptpilot --include metadata.toml fde.toml`。在 GCP 镜像上换 gcp 内核后，`/boot/vmlinuz` 仍指向 **generic** 内核，于是：
- generic 内核 initrd：**有** `91cryptpilot` 模块（cryptpilot-fde-before-sysroot.service 等）；
- gcp 内核 initrd：由包 postinst 重建，**没有** cryptpilot 模块；
- 而 grub 默认按版本号启动 **gcp** 内核 → 启动的 initrd 里 cryptpilot 栈完全缺席。

**后果（实测确认，非隐患）**：启动 gcp 内核时 `cryptpilot-fde-before-sysroot.service` 不运行 →
1. 不建可写层 → rootfs 只读 → cloud-init/docker/snapd 等全部失败；
2. **RTMR 完全未 extend**（measure 阶段在该 service 内，根本没跑）；
3. **dm-verity 完整性校验被绕过**，直接挂裸 LV —— 机密计算保障失效。

**临时规避**：convert 前把 `/boot/vmlinuz`/`initrd.img` 软链指向 gcp 内核（见 §5 修复 A）。
**建议**：convert 应以 **grub 默认/将实际启动的内核** 为 dracut 目标，而非 `/boot/vmlinuz` 软链；或显式接受 `--kernel-version` 参数。

**7.4 chroot 内 dracut 继承宿主 TMPDIR 导致失败**
若调用方环境 `TMPDIR` 指向 chroot 内不存在的路径（如 CI 容器的 `/tmp/xxx`），chroot 内 dracut 报 `Invalid tmpdir` 而失败，并触发 7.2 的中止分支。建议 convert 在 chroot 内显式设置合法 `TMPDIR`（如 `/tmp`）。

**7.5 `rw_overlay="ram"` 运行时未生效（已解决，归因于 7.3）**
此前观察到 rootfs 只读、`rw_overlay` 不生效，曾疑为独立问题。实为 **7.3 的表现**：可写层由 `cryptpilot-fde-before-sysroot.service` 在 initrd 里建立，而该 service 不在所启动 gcp 内核的 initrd 中，故未运行。应用修复 A 后，QEMU 实测可写层（zram + dm-snapshot）正常建立、`Read-only file system` 错误归零。非独立 bug。

**7.6 `show-reference-value` 硬性要求 grubenv 里有 `saved_entry`（参考值提取）**
`cryptpilot-fde show-reference-value` 在 `load_kernel_artifacts`（`src/cmd/fde/disk.rs:395-397`）里：
```rust
let saved_entry = grub_vars
    .get("saved_entry")
    .ok_or_else(|| anyhow::anyhow!("saved_entry not found in GRUB environment"))?;
```
**问题**：刚构建、从未启动过的镜像 grubenv 为空 → 直接报 `saved_entry not found in GRUB environment`，无法提取启动项的内核/initrd/cmdline 参考值。而这些镜像的 grub.cfg 默认选择逻辑是 `set default="0"`（与 `saved_entry` 无关），grub 实际启动的就是第一条 menuentry。

**正确修复（在消费者侧，不碰镜像）**：`saved_entry` 缺失时按 grub 真实默认逻辑回落——`next_entry > saved_entry > set default(=0) > 第一条 menuentry`，再据此从 grub.cfg/loader entry 解析；而不是 `?` 报错。

**⚠️ 当前的本地 workaround（不推荐作为正式修复）**：在 `cryptpilot-convert` 的 `update_rootfs_inner` 末尾，从 grub.cfg 第一条 menuentry 提取 id 并写进 grubenv 的 `saved_entry`（正则 `'\K[^']+(?=' \{)`）。它**改错了层**（改生产者 + 改镜像内容去迁就消费者的严格检查），且 `saved_entry` 本是运行时状态、不应构建期伪造。仅用于让本机构建跑通，正解应在 `disk.rs` 上述位置。

## 8. 另一侧修复：tapp-server / guest-components 的 RTMR 扩展探测误判

> 与上面镜像构建（convert/grub）问题相互独立。即使镜像侧全部修好（内核具备接口、cryptpilot 栈在正确 initrd 中），运行时 RTMR 仍会失败，根因在 **应用侧 `tapp-server` 依赖的 guest-components**。

**症状**：app 启动后 `tapp-server` 调用 extend RTMR 报：
```
Failed to extend measurement: Internal error: TDX Attester: Cannot extend runtime measurement on this system
    at src/boot/mod.rs:257
```

**根因**：`Cargo.lock` 钉住的 `guest-components@5683fa5` 中的启发式判断有误：
```rust
fn runtime_measurement_extend_available() -> bool {
    if Path::new("/sys/kernel/config/tsm/report").exists() {
        return false;   // 存在 TSM report 就认为内核不支持 RTMR 扩展
    }
    true
}
```
该逻辑假设"有 TSM report sysfs ⇒ 内核不支持 RTMR 扩展"。但 Linux 6.17 上 **TSM report 与 RTMR 扩展两者都支持**，于是被误判为不可用 → 直接报 "Cannot extend runtime measurement on this system"。

**修复**：将 guest-components 更新到 `8d71a3b4`，新版改为检查实际可用路径：
```rust
fn runtime_measurement_extend_available() -> bool {
    Path::new("/dev/tdx_guest").exists() ||
    Path::new("/sys/devices/virtual/misc/tdx_guest/measurements").exists()
}
```

**操作步骤**：
1. 拉取最新 `fix/volume-path-and-cli-relative-paths` 分支；
2. `cargo update -p attestation-agent` 更新 lock 文件；
3. 安装构建依赖：`libtdx-attest-dev`、`protobuf-compiler`；
4. 重新构建并替换 `/usr/local/bin/tapp-server`。

**结果**：真 TDX 上 RTMR extend 成功。

> 说明：这印证了 §2 的判断——`6.17.0-1018-gcp` 内核本身具备 RTMR extend 接口（`/dev/tdx_guest` + `/sys/devices/virtual/misc/tdx_guest/measurements/`），此前失败纯属 guest-components 的误判，与内核/convert 无关。

## 9. 完整 build 流程（裸 Ubuntu 24.04 → gcp-tapp.qcow2）

把上面所有修复整合成一条可复现流水线。分两段：**段A** 把裸镜像装成 base（应用 + 依赖 + DNS），**段B** 换内核 + convert + 同步 ESP。全程在宿主机用 `virt-customize`/`guestfish`/`cryptpilot-convert` 离线操作。

**前置物料**（与脚本同目录）：
- 裸 `ubuntu-24.04` cloud 镜像（generic 内核，无应用）；
- `config_dir/`（含 `fde.toml`，`rw_overlay="ram"`）；
- `cryptpilot-fde_0.7.0_amd64.deb`；
- `tapp-server`（GitHub release **v0.0.5**，已含 guest-components `8d71a3b4` 修复，见 §8）。

> 全程需 `export LIBGUESTFS_BACKEND=direct`（否则 libguestfs 走 libvirt 后端会因权限失败）。

### 段A：裸镜像 → base（应用与依赖）

1. **tapp-server**：`virt-customize --upload tapp-server:/usr/local/bin/tapp-server --chmod 0755:/usr/local/bin/tapp-server`
2. **service**：上传 `tapp-server.service` 到 `/etc/systemd/system/`，`systemctl enable tapp-server`
3. **`/etc/tapp/config.toml`**：`--mkdir /etc/tapp` + 上传 config（含 `owner_address`、`[kbs] node_urls`）
4. **Intel SGX 源 + `libtdx-attest`**（tapp-server 运行时依赖，TDX attest）：
   ```bash
   curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
     | gpg --dearmor -o /etc/apt/keyrings/intel-sgx.gpg
   echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
     > /etc/apt/sources.list.d/intel-sgx.list
   apt-get update && apt-get install -y libtdx-attest
   ```
5. **Docker**（官方源 `docker-ce` 全家桶）
6. **DNS**（关键，见下方注意）：systemd-resolved `FallbackDNS` 兜底 + **静态 `/etc/resolv.conf`**

> **⚠️ DNS 必须用 guestfish 写 `/etc/resolv.conf`，不能用 virt-customize。**
> 现象：实例 DNS 不通（`Temporary failure in name resolution`），需手动 `echo nameserver 8.8.8.8 > /etc/resolv.conf`。原因：该镜像里 systemd-resolved 的 stub 未真正服务，`FallbackDNS` 无效；唯一可靠解是把 `/etc/resolv.conf` 做成**静态文件**。但 **`virt-customize` 为 `--run-command` 联网会临时放一份 resolv.conf 并在收尾删掉**——用它写（无论 `printf`/`for`）最终都是空/不存在。`cryptpilot-convert` 也会备份原 resolv.conf→bind-mount 主机的→收尾恢复。
> 正确做法：用 **guestfish** 写（不做这套），且放在**所有 virt-customize 之后、convert 之前**；convert 的备份/恢复会保留它：
> ```bash
> printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n' > /tmp/resolv
> guestfish --rw -a <img> <<'GF'
> run
> mount /dev/sda1 /
> rm-f /etc/resolv.conf
> upload /tmp/resolv /etc/resolv.conf
> GF
> ```

7. **安全加固**（移除可绕过 tapp 改环境的软件）：`apt-get purge` Tier1/2 包 + `systemctl mask` 控制台 getty + 替换 netplan 为 MAC 无关 DHCP，详见 **§11**。

### 段B：base → gcp-tapp（内核 + convert + ESP）

1. **装 gcp 内核**：`virt-customize --install linux-image-gcp,linux-modules-extra-gcp`（保留至少一个 `-generic`，convert 的 line-448 检查需要）
2. **修复 A**：`/boot/vmlinuz`、`initrd.img` 软链指向 gcp 内核（见 §5/§7.3）
3. **DNS**（若段A未做则在此用 guestfish 写静态 resolv.conf）
4. **nbd 重置**（convert 用 qemu-nbd 挂盘，避免残留/缺 max_part）：
   ```bash
   qemu-nbd -d /dev/nbd0; qemu-nbd -d /dev/nbd1; rmmod nbd; modprobe nbd max_part=16; partprobe /dev/nbd0
   ```
5. **convert**：`cryptpilot-convert --in <base> --out gcp-tapp.qcow2 --config-dir ./config_dir/ --rootfs-no-encryption --package cryptpilot-fde_0.7.0_amd64.deb`
   （若调用方 `TMPDIR` 指向 chroot 内不存在的路径，需 `TMPDIR=/tmp`，见 §7.4）
6. **修复 B**：`fix-esp-grub.sh gcp-tapp.qcow2`（同步 ESP，见 §5/§10）

### 一键脚本

仓库提供三个脚本：
- **`build-gcp-tapp.sh <裸ubuntu.qcow2> <out.qcow2>`** —— 串起段A+段B 全流程；
- **`prepare-gcp-tapp.sh <base.qcow2> <out.qcow2>`** —— 仅段B（已有 base 时用）；含修复A、DNS(guestfish)、nbd 重置、convert、修复B；
- **`fix-esp-grub.sh <img.qcow2>`** —— 仅同步 ESP（修复B）。

```bash
# 裸 Ubuntu 24.04 → 最终 gcp-tapp.qcow2（一条命令）
./build-gcp-tapp.sh ubuntu-24.04.qcow2 gcp-tapp.qcow2
```
关键环境变量：`TAPP_SERVER_BIN`（本地 tapp-server，留空则下 v0.0.5）、`DNS_FALLBACK`、`PURGE_KERNEL`、`CONFIG_DIR`、`FDE_PACKAGE`、`ROOTFS_MODE`、`IN_PLACE`（1=直接改输入不复制）、`INSTALL_KERNEL`、`NBD_RESET`。

### 产物验证清单（已全部通过）

| 检查 | 命令/方法 | 期望 |
|---|---|---|
| gcp initrd 含 cryptpilot | `lsinitrd initrd.img-*-gcp \| grep -c cryptpilot` | 16（含 `cryptpilot-fde-before-sysroot.service`） |
| ESP 默认项 | `cat /EFI/ubuntu/grub.cfg`(sda15) | 指向 `vmlinuz-*-gcp` + `rd.neednet=1 ip=dhcp` |
| verity | `list-filesystems` | `/dev/cryptpilot/rootfs`(ext4) + `rootfs_hash`(DM_verity_hash) |
| **`/etc/resolv.conf`** | 挂 verity LV(`vg-activate-all`) 后 `cat` | **静态文件，3 行 nameserver**（非空、非软链） |
| tapp-server | `strings tapp-server \| grep guest-components` | `…/8d71a3b`（修复版） |
| docker/libtdx | `ls /usr/bin/dockerd /usr/lib/.../libtdx_attest.so.1` | 存在 |

> 真 TDX 上还需确认：`journalctl \| grep -i rtmr` 显示 extend 成功；`getent hosts github.com` 能解析。

## 10. 附：临时修复脚本 `fix-esp-grub.sh`

```bash
#!/bin/bash
# 把 boot 分区最新 grub.cfg + 模块同步到 GCP 镜像的 ESP，修复换内核后启动崩溃。
# 仅读写 ESP(sda15)/boot(sda16)，不碰 verity rootfs；幂等。放在 convert 之后执行。
set -euo pipefail
IMG="${1:?用法: $0 <image.qcow2>}"
export LIBGUESTFS_BACKEND=direct
guestfish --rw -a "$IMG" <<'GF'
run
mount /dev/sda16 /
mount /dev/sda15 /efi
is-file /grub/grub.cfg
is-dir  /efi/EFI/ubuntu
rm-f /efi/EFI/ubuntu/grub.cfg.stale
mv   /efi/EFI/ubuntu/grub.cfg /efi/EFI/ubuntu/grub.cfg.stale
cp   /grub/grub.cfg /efi/EFI/ubuntu/grub.cfg
rm-rf /efi/EFI/ubuntu/x86_64-efi
cp-a  /grub/x86_64-efi /efi/EFI/ubuntu/x86_64-efi
GF
echo "[OK] ESP grub 已同步: $IMG"
```

## 11. 安全加固：移除可绕过 tapp 改变实例环境的软件

机密 appliance 的目标是"除了经 tapp 的受测路径，外部无法改变实例内部环境"。GCP Ubuntu 镜像默认带大量**带外访问 / metadata 驱动改环境**的组件，需在 **convert 之前**（rootfs 被 verity 密封后不可改）从 base 移除。

**审计（在产物 rootfs 上 `dpkg`/枚举 systemd 启用项得出）与处置：**

| 层级 | 组件 | 风险（如何绕过 tapp） | 处置 |
|---|---|---|---|
| 🔴 T1 | `openssh-server`(ssh.socket) | 远程 shell | purge |
| 🔴 T1 | `google-guest-agent` | 从 metadata 注入 SSH key/账号、OS Login | purge |
| 🔴 T1 | `google-compute-engine`(+startup/shutdown-scripts) | 从 metadata 跑任意启动/关机脚本（最强后门） | purge |
| 🔴 T1 | `google-osconfig-agent` | GCP 远程下发包/补丁/策略 | purge |
| 🔴 T1 | `google-compute-engine-oslogin` | OS Login（IAM→SSH） | purge |
| 🔴 T1 | `cloud-init` | 从 metadata/user-data 建用户、写文件、执行命令 | purge |
| 🔴 T1 | `serial-getty@ttyS0` | GCP 串口控制台登录 | mask |
| 🟠 T2 | `snapd` | 远程装/刷新 snap | purge + 清 /snap |
| 🟠 T2 | `unattended-upgrades` | 自动改包 | purge |
| 🟠 T2 | `open-vm-tools` | hypervisor→guest 操作 | purge |
| 🟠 T2 | `google-cloud-ops-agent` | 监控/日志外发 | purge |
| 🟠 T2 | `pollinate` | 启动联外部服务器 | purge |
| 🟠 T2 | `landscape-common`/`ubuntu-pro-client` | Canonical 管理/订阅 agent | purge |

> 🟡 T3（按需评估，暂保留）：`cron`、`networkd-dispatcher`、`apport`、`lxd-installer.socket`、`rpcbind`/`nfs-client`、`polkitd`。
> 🟢 保留：`tapp-server`、`docker`/`containerd`（应用运行时）、`systemd-networkd`、`ufw`、`rsyslog` 等。

**⚠️ 配套（必做）：移除 `cloud-init` 后必须替换 netplan。**
GCP 镜像的 `/etc/netplan/50-cloud-init.yaml` **按构建时 MAC 匹配网卡**，靠 cloud-init 每次开机按新实例重生成。一旦删掉 cloud-init，新实例 MAC 变了就不匹配 → networkd 不管网卡 → **无网**。故同时删除该文件、换成 MAC 无关的 DHCP：
```yaml
# /etc/netplan/01-dhcp.yaml
network:
  version: 2
  ethernets:
    alleth:
      match: { name: "e*" }
      dhcp4: true
      dhcp6: false
```
（DNS 仍靠 §9 的静态 `/etc/resolv.conf`。）

以上加固已集成在 `build-gcp-tapp.sh` 段A 末尾（`apt-get purge` + `systemctl mask` + 替换 netplan），随 convert 一并密封进 verity 测量层。
