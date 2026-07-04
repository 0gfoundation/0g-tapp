# cryptpilot-convert boot crash after switching the kernel on a GCP Ubuntu image — root-cause analysis and fix

> Goal: switch the kernel (generic → gcp) to enable **RTMR extend** on a GCP Ubuntu image. Along the way we hit four classes of problems, all now resolved, and RTMR extend has been confirmed working on real TDX:
> 1. **Image boot crash** (grub cannot find the kernel/modules) — root cause is GCP's dual grub.cfg, see §4 / §5 fix B;
> 2. **read-only rootfs / RTMR not extended / verity bypassed** — root cause is convert installing the cryptpilot stack into the wrong kernel's initrd, see §7.3 / §5 fix A;
> 3. **runtime RTMR extend failure** ("Cannot extend runtime measurement") — root cause is a misdetection in the application-side guest-components, see §8;
> 4. **instance DNS broken** (requires a manual `echo nameserver … > /etc/resolv.conf`) — root cause is virt-customize cleaning up resolv.conf during teardown and the resolved fallback being ineffective; a static resolv.conf must be written with guestfish, see §9.
>
> §1–§7 cover the image-build side (including convert issues to confirm with the cryptpilot maintainers), §8 covers the application-side (guest-components) fix, **§9 is the complete reproducible build flow (SOP)**, §10 is the script appendix.

---

## 0. Preparation

### 0.1 Build / conversion host

`cryptpilot-convert` is packaged only for **Anolis / Alibaba Cloud Linux 3 (al8)**, so the conversion must run on such a host (e.g. an Alibaba Cloud ECS running Alibaba Cloud Linux 3, or an Anolis 8 VM). A plain Ubuntu/macOS host cannot run `cryptpilot-convert`.

On that host:

```bash
# 1) cryptpilot-convert itself (host tool), from the openanolis/cryptpilot v0.7.0 release:
#    https://github.com/openanolis/cryptpilot/releases/tag/v0.7.0
sudo rpm -i cryptpilot-fde-0.7.0-1.al8.x86_64.rpm     # provides /usr/bin/cryptpilot-convert

# 2) host tooling used by the build scripts
sudo dnf install -y libguestfs-tools qemu-img         # guestfish, virt-customize, qemu-img, qemu-nbd
sudo modprobe nbd max_part=16
export LIBGUESTFS_BACKEND=direct                       # required for libguestfs in this environment
# docker is only needed for the local boot smoke test (test/boot-smoke-test.sh)
```

Run the build as **root** (libguestfs direct backend + nbd + chroot in convert).

Materials to place in `gcp-cvm/` (gitignored binaries, not committed):
- `cryptpilot-fde_0.7.0_amd64.deb` — the FDE **runtime installed into the target Ubuntu image** (passed via `--package`). From the same [v0.7.0 release](https://github.com/openanolis/cryptpilot/releases/tag/v0.7.0). Note this is the `.deb` for the *target image*, distinct from the `.al8.rpm` for the *host* above.
- `tapp-server` — pulled automatically from the 0g-tapp v0.1.0 release by `build-gcp-tapp.sh`, or supply a local one via `TAPP_SERVER_BIN=<path>`.

### 0.2 Base Ubuntu image

The input to the build pipeline below is a base image produced **reproducibly from the official Ubuntu cloud image**: the official Ubuntu 24.04 (noble) cloud image, resized to 20 GiB, with the GCP gVNIC network driver installed (required for GCP Confidential VMs). Build it from the official image with the steps below — do not rely on any pre-built/opaque base blob, so the whole image stays reproducible and attestable.

Material:
- Ubuntu cloud image: https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

Resize the root partition to 20 GiB (the stock cloud image ships a ~3.5 GiB disk, too small for the kernel + application + Docker layers added later). Use `qemu-img resize` + `growpart` + `resize2fs` so the partition **numbering is preserved** — do **not** use `virt-resize --expand`, which renumbers the partitions (e.g. `sda1` → `sda4`) and breaks the `sda1`=rootfs / `sda16`=/boot assumptions the rest of this flow relies on:
```bash
qemu-img resize noble-server-cloudimg-amd64.img 20G
# grow the in-image partition table + filesystem in place (keeps sda1/sda16 numbering)
sudo virt-customize -a noble-server-cloudimg-amd64.img \
  --run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1'
```

Prepare the Ubuntu image for a GCP Confidential VM (install the gVNIC driver):
```bash
sudo apt install dkms build-essential linux-headers-$(uname -r)
sudo apt --fix-broken install

# download the latest gVNIC driver
wget https://github.com/GoogleCloudPlatform/compute-virtual-ethernet-linux/releases/download/v1.4.9/gve-dkms_1.4.9_all.deb

# install the gVNIC driver
sudo dpkg -i gve-dkms_1.4.9_all.deb

# load the new gVNIC driver
sudo modprobe gve

# confirm the driver loaded (output should be similar to "gve  159744  0")
sudo lsmod | grep -i gve
```

> Note on SSH access — the stock Ubuntu cloud image relies on `google-guest-agent` to inject the instance's SSH public key (from the metadata server, via the `169.254.169.254` IP — independent of DNS) into `~ubuntu/.ssh/authorized_keys`. Because the build pins `/etc/resolv.conf` to public DNS (fix C, §9), `metadata.google.internal` no longer resolves, so a `169.254.169.254 metadata.google.internal` line in `/etc/hosts` is also needed for the agent to reach the metadata server by name. The build handles this **only for the dev variant** (`HARDEN=0`): it (re)installs `google-guest-agent` and adds the `/etc/hosts` line. The hardened variant intentionally omits both — `google-guest-agent` is exactly the kind of component that can push changes into the instance from outside, so the hardened image is not SSH-reachable by design.

The full build (`gcp-cvm/build-gcp-tapp.sh`, §9) then takes this base image and adds the application, Docker, the gcp kernel, runs `cryptpilot-convert`, syncs the ESP, and (for the hardened variant) removes back-door software.

## 1. Environment

| Item | Value |
|---|---|
| Base image | GCP Ubuntu 24.04 cloud image |
| Disk layout | `sda1`=rootfs(ext4), `sda14`=bios-grub, `sda15`=**ESP/EFI**(vfat), `sda16`=**/boot**(ext4) |
| Original kernel | `6.8.0-106-generic` |
| Target kernel | `linux-image-gcp` → actually `6.17.0-1018-gcp` |
| Conversion tool | `cryptpilot-convert`, provided by **cryptpilot-fde 0.7.0** (on the conversion host it is `cryptpilot-fde-0.7.0-1.al8`; the one installed into the target image is `cryptpilot-fde_0.7.0_amd64.deb`) |
| attestation-agent | Actual version inside the target image **to be confirmed** (used for `ExtendRuntimeMeasurement`) |
| Conversion parameters | `--rootfs-no-encryption` (measuring only, no encryption) |

## 2. Original requirement: why switch the kernel

cryptpilot extends RTMR via the attestation-agent (AA) `ExtendRuntimeMeasurement` interface; AA's TDX attester takes one of two paths:

1. ioctl: `TDX_CMD_EXTEND_RTMR` on `/dev/tdx_guest`
2. sysfs (fallback): `/sys/devices/virtual/misc/tdx_guest/measurements/rtmr{N}:sha384`

But the `tdx_guest` uapi of the original generic kernel `6.8.0-106` (`/usr/src/linux-headers-*/include/uapi/linux/tdx-guest.h`) **only defines `TDX_CMD_GET_REPORT0`** — it has neither the extend ioctl nor the sysfs measurement interface above → **RTMR cannot be extended**.

- The extend ioctl (`TDX_CMD_EXTEND_RTMR`) is an Intel/Anolis out-of-tree patch that never landed in mainline Linux;
- The sysfs measurement interface was introduced with the mainline TSM measurement register framework (around 6.14).

Testing confirmed that the target kernel `6.17.0-1018-gcp` has the kernel config `CONFIG_TSM_MEASUREMENTS=y`, `CONFIG_TSM_GUEST=y`, `CONFIG_TSM_REPORTS=y`, `CONFIG_INTEL_TDX_GUEST=y`, `CONFIG_TDX_GUEST_DRIVER=m`, meeting the prerequisites for the sysfs RTMR extend interface. Switching to this kernel to obtain the extend capability is therefore the right direction.

> Note: switching the kernel only addresses the "kernel-side interface missing" issue. RTMR still failed once on real TDX, the root cause being a **misdetection in the application-side guest-components** (see §8). Both the **image side (§5 fixes A/B) and the application side (§8)** must be fixed before RTMR extend succeeds.

## 3. Failure symptoms

The image with the switched kernel reports at boot:

```
error: file '/EFI/ubuntu/x86_64-efi/bli.mod' not found.
error: file '/vmlinuz-6.8.0-106-generic' not found.
error: you need to load the kernel first.
Failed to boot both default and fallback entries.
```

Note that `vmlinuz-6.8.0-106-generic` is the **old kernel that has already been purged**.

## 4. Root cause

The GCP Ubuntu image has **two grub.cfg files**:

| File | Location | Who updates it | Read by grub at boot |
|---|---|---|---|
| `/boot/grub/grub.cfg` | boot partition sda16 | `update-grub` / `cryptpilot-convert` | No |
| `/EFI/ubuntu/grub.cfg` | **ESP partition sda15** | only `grub-install` (typically generated once at build time) | **Yes (grubx64.efi prefix=`/EFI/ubuntu`)** |

- `update-grub` (and the update-grub called internally by `cryptpilot-convert`) **only writes `/boot/grub/grub.cfg`**, not the one on the ESP;
- After switching the kernel and purging the old one, the grub.cfg on the ESP still points to the deleted `6.8.0-106-generic` → `vmlinuz not found`;
- The ESP has no `x86_64-efi/` module directory (`insmod bli` comes from `/etc/grub.d/25_bli`) → `bli.mod not found` (not fatal, but it shows the ESP grub environment is incomplete).

**This is not directly related to cryptpilot — it stems from the GCP image grub layout plus update-grub behavior**; however, cryptpilot-convert also calls update-grub internally, so the problem still reproduces after conversion.

## 5. Fix (end-to-end verified)

**Two independent fix points are required, neither optional**:

**Fix A — before convert, point the `/boot/vmlinuz` symlink at the gcp kernel** (resolves read-only / RTMR not extended / verity bypassed, see §7.3):
After installing `linux-image-gcp` on the GCP image, `/boot/vmlinuz` still points at the generic kernel; convert selects the kernel via this symlink to run `dracut --add cryptpilot`, so the cryptpilot stack ends up in the generic kernel's initrd, while the gcp kernel that grub boots by default has no cryptpilot in its initrd. Repointing the symlink at gcp makes convert build the initrd for the correct kernel.

**Fix B — after convert, sync the boot-partition grub.cfg + modules to the ESP** (resolves the boot crash, see §4):
```
cp    /boot/grub/grub.cfg   /EFI/ubuntu/grub.cfg          # sync the latest config
cp -a /boot/grub/x86_64-efi /EFI/ubuntu/x86_64-efi        # sync grub modules (fixes bli.mod)
```

Full flow:
```bash
# 1) switch the kernel + point the default kernel symlink at gcp (fix A: the final ln is the key line)
virt-customize -a gcp-base.qcow2 \
  --install linux-image-gcp,linux-modules-extra-gcp \
  --run-command 'apt-get autoremove --purge linux-image-6.8.0-106-generic -y || true' \
  --run-command 'update-grub' \
  --run-command 'k=$(ls /boot/vmlinuz-*-gcp | sort -V | tail -1 | sed "s#/boot/##"); ln -sf "$k" /boot/vmlinuz; ln -sf "initrd.img-${k#vmlinuz-}" /boot/initrd.img'

# 2) convert (mind TMPDIR, see §7.4)
TMPDIR=/tmp cryptpilot-convert --in gcp-base.qcow2 --out gcp-tapp.qcow2 \
  --config-dir ./config_dir/ --rootfs-no-encryption \
  --package cryptpilot-fde_0.7.0_amd64.deb

# 3) sync the ESP (fix B, must run after convert; convert internally only updates the boot-partition copy)
./fix-esp-grub.sh gcp-tapp.qcow2
```

> Ordering constraint: if you need to compute reference values with `cryptpilot-fde show-reference-value`, it must be run **after** step 3 (see §6).

**Verification (QEMU software emulation, KVM=N)**:
- Fix B only (without A): grub can boot 6.17-gcp, but `cryptpilot-fde-before-sysroot.service` is not in the gcp initrd → it does not run → rootfs is read-only, the screen fills with `Read-only file system`, cloud-init/docker/snapd all fail, and neither verity nor RTMR takes effect.
- Both A+B: `cryptpilot-fde-before-sysroot` runs normally (activate LVM → load root-hash → build dm-verity → build zram + dm-snapshot writable layer), the `Read-only` errors drop to zero, and boot reaches login.
- RTMR extend: image-side A+B removes the blocker of a missing cryptpilot stack in the initrd; success on real TDX additionally requires the application-side fix (the guest-components update in §8). With both sides in place, extend has been confirmed working.

## 6. Impact on image integrity / measurement

| Aspect | Impact | Notes |
|---|---|---|
| rootfs dm-verity / `root_hash` | **Not affected** | The ESP and /boot are outside verity's protection scope; the script does not touch verity data or the hash tree, and the root_hash embedded in the initrd is unchanged |
| qcow2 / filesystem structure | **Not corrupted** | Mounted/unmounted properly via guestfish; only files are written to the vfat ESP |
| boot-time RTMR measurement | **Changes (expected)** | grub measures kernel/initrd/cmdline into RTMR; syncing the ESP changes grub.cfg (the cmdline includes `rd.neednet=1 ip=dhcp`) → the measurement changes accordingly |

**Conclusion**: rootfs integrity is not broken and the image is not corrupted; only the boot-time measurement changes. As long as you **run step 3 first, then compute the reference values**, you guarantee "reference value == actual boot measurement". Conversely, if step 3 is skipped, the ESP config is stale and either boot crashes or the actual boot differs from the reference value, causing remote attestation to fail.

## 7. Questions to confirm with the cryptpilot maintainers

The following are convert-side issues observed when using `cryptpilot-convert` on Ubuntu/GCP images. We recommend confirming whether they should be fixed inside convert so it natively supports this scenario:

**7.1 convert does not sync the grub.cfg on the ESP (core)**
convert internally calls `update-grub`, which only updates `/boot/grub/grub.cfg` and does not sync the `/EFI/ubuntu/grub.cfg` on the GCP image's ESP. We suggest that after updating grub, convert detect and sync the ESP copy (or ensure a UKI mode that bypasses grub).

**7.2 kernel-version detection hardcodes `-generic`**
(the zram-module install section in `cryptpilot-convert`, around line 448)
```bash
kernel_version=$(chroot ... "dpkg -l | grep -oP 'linux-image-\K[0-9.-]+-generic' | head -n1")
if [ -z "$kernel_version" ]; then ... return 1; fi
```
This regex only matches `-generic` kernels; with `-gcp` (or other flavors) it grabs a leftover generic or returns empty and aborts. We suggest detecting the actual default kernel flavor instead.

**7.3 [core bug] the dracut target kernel differs from the grub default boot kernel → the cryptpilot stack is installed into the wrong kernel**
(around lines 1069–1081) convert selects the kernel via the `/boot/vmlinuz` symlink and runs `dracut --add cryptpilot --include metadata.toml fde.toml`. After switching to the gcp kernel on the GCP image, `/boot/vmlinuz` still points at the **generic** kernel, so:
- generic kernel initrd: **has** the `91cryptpilot` module (cryptpilot-fde-before-sysroot.service, etc.);
- gcp kernel initrd: rebuilt by the package postinst, **without** the cryptpilot module;
- yet grub boots the **gcp** kernel by version → the booted initrd is entirely missing the cryptpilot stack.

**Consequences (confirmed in testing, not hypothetical)**: when the gcp kernel boots, `cryptpilot-fde-before-sysroot.service` does not run →
1. no writable layer is built → rootfs is read-only → cloud-init/docker/snapd etc. all fail;
2. **RTMR is never extended** (the measure stage lives inside that service and simply never runs);
3. **dm-verity integrity checking is bypassed** and the bare LV is mounted directly — confidential-computing guarantees are voided.

**Temporary workaround**: before convert, point the `/boot/vmlinuz` / `initrd.img` symlinks at the gcp kernel (see §5 fix A).
**Suggestion**: convert should make the dracut target the **grub default / actually-booting kernel**, not the `/boot/vmlinuz` symlink; or accept an explicit `--kernel-version` parameter.

**7.4 dracut inside chroot inherits the host TMPDIR and fails**
If the caller's environment has `TMPDIR` pointing at a path that does not exist inside the chroot (e.g. a CI container's `/tmp/xxx`), dracut inside the chroot reports `Invalid tmpdir` and fails, triggering the abort branch from 7.2. We suggest convert explicitly set a valid `TMPDIR` (e.g. `/tmp`) inside the chroot.

**7.5 `rw_overlay="ram"` not effective at runtime (resolved, attributed to 7.3)**
We previously observed a read-only rootfs and `rw_overlay` not taking effect, and suspected an independent issue. It was actually a **manifestation of 7.3**: the writable layer is created by `cryptpilot-fde-before-sysroot.service` in the initrd, and that service is not in the booted gcp kernel's initrd, so it never runs. After applying fix A, QEMU testing confirmed the writable layer (zram + dm-snapshot) is built normally and the `Read-only file system` errors drop to zero. Not an independent bug.

**7.6 `show-reference-value` rigidly requires `saved_entry` in grubenv (reference-value extraction)**
In `cryptpilot-fde show-reference-value`, inside `load_kernel_artifacts` (`cryptpilot-fde/src/disk/grub.rs`):
```rust
let saved_entry = grub_vars
    .get("saved_entry")
    .ok_or_else(|| anyhow::anyhow!("saved_entry not found in GRUB environment"))?;
```
**Problem**: a freshly built image that has never booted has an empty grubenv → it directly reports `saved_entry not found in GRUB environment`, and the kernel/initrd/cmdline reference values of the boot entry cannot be extracted. Yet the default-selection logic of these images' grub.cfg is `set default="0"` (independent of `saved_entry`), and the entry grub actually boots is the first menuentry.

**Correct fix (on the consumer side, without touching the image)**: when `saved_entry` is missing, fall back per grub's real default logic — `next_entry > saved_entry > set default(=0) > first menuentry` — and then parse the grub.cfg / loader entry accordingly, rather than erroring with `?`.

**⚠️ Current local workaround (not recommended as the official fix)**: at the end of `cryptpilot-convert`'s `update_rootfs_inner`, extract the id from the first menuentry in grub.cfg and write it into grubenv's `saved_entry` (regex `'\K[^']+(?=' \{)`). This **fixes the wrong layer** (modifying the producer + modifying the image content to accommodate the consumer's strict check), and `saved_entry` is runtime state that should not be fabricated at build time. Use it only to get the local build to pass; the proper fix belongs at the `disk.rs` location above.

## 8. The other-side fix: RTMR-extend misdetection in tapp-server / guest-components

> Independent of the image-build (convert/grub) issues above. Even if the image side is fully fixed (kernel has the interface, the cryptpilot stack is in the correct initrd), runtime RTMR still fails, the root cause being the guest-components that the application-side `tapp-server` depends on.

**Symptom**: after the app starts, `tapp-server` calling extend RTMR reports:
```
Failed to extend measurement: Internal error: TDX Attester: Cannot extend runtime measurement on this system
    at src/boot/mod.rs:257
```

**Root cause**: the heuristic in `guest-components@5683fa5` (pinned by `Cargo.lock`) is wrong:
```rust
fn runtime_measurement_extend_available() -> bool {
    if Path::new("/sys/kernel/config/tsm/report").exists() {
        return false;   // presence of a TSM report is taken to mean the kernel does not support RTMR extend
    }
    true
}
```
This logic assumes "TSM report sysfs present ⇒ kernel does not support RTMR extend". But on Linux 6.17 **both TSM report and RTMR extend are supported**, so it is misdetected as unavailable → it directly reports "Cannot extend runtime measurement on this system".

**Fix**: update guest-components to `8d71a3b4`, which instead checks the actually-available paths:
```rust
fn runtime_measurement_extend_available() -> bool {
    Path::new("/dev/tdx_guest").exists() ||
    Path::new("/sys/devices/virtual/misc/tdx_guest/measurements").exists()
}
```

**Steps**:
1. Pull the latest `fix/volume-path-and-cli-relative-paths` branch;
2. `cargo update -p attestation-agent` to update the lock file;
3. Install build dependencies: `libtdx-attest-dev`, `protobuf-compiler`;
4. Rebuild and replace `/usr/local/bin/tapp-server`.

**Result**: RTMR extend succeeds on real TDX.

> Note: this confirms the judgment in §2 — the `6.17.0-1018-gcp` kernel itself has the RTMR extend interface (`/dev/tdx_guest` + `/sys/devices/virtual/misc/tdx_guest/measurements/`); the earlier failure was purely a guest-components misdetection, unrelated to the kernel/convert.

## 9. Complete build flow (bare Ubuntu 24.04 → gcp-tapp.qcow2)

This integrates all the fixes above into one reproducible pipeline, in two stages: **stage A** turns the bare image into a base (app + dependencies + DNS), **stage B** switches the kernel + convert + syncs the ESP. Everything runs offline on the host with `virt-customize` / `guestfish` / `cryptpilot-convert`.

**Prerequisite materials** (in the same directory as the scripts):
- bare `ubuntu-24.04` cloud image (generic kernel, no app);
- `config_dir/` (containing `fde.toml`, `rw_overlay="ram"`);
- `cryptpilot-fde_0.7.0_amd64.deb`;
- `tapp-server` (GitHub release **v0.1.0**, already includes the guest-components `8d71a3b4` fix, see §8).

> Throughout, `export LIBGUESTFS_BACKEND=direct` is required (otherwise libguestfs uses the libvirt backend and fails on permissions).

### Stage A: bare image → base (app and dependencies)

1. **tapp-server**: `virt-customize --upload tapp-server:/usr/local/bin/tapp-server --chmod 0755:/usr/local/bin/tapp-server`
2. **service**: upload `tapp-server.service` to `/etc/systemd/system/`, `systemctl enable tapp-server`
3. **`/etc/tapp/config.toml`**: `--mkdir /etc/tapp` + upload config (includes `owner_address`, `[kbs] node_urls`)
4. **Intel SGX repo + `libtdx-attest`** (tapp-server runtime dependency, TDX attest):
   ```bash
   curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
     | gpg --dearmor -o /etc/apt/keyrings/intel-sgx.gpg
   echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
     > /etc/apt/sources.list.d/intel-sgx.list
   apt-get update && apt-get install -y libtdx-attest
   ```
5. **Docker** (the full official `docker-ce` set)
6. **DNS** (critical, see the note below): systemd-resolved `FallbackDNS` + a **static `/etc/resolv.conf`**

> **⚠️ DNS must be written to `/etc/resolv.conf` with guestfish, not virt-customize.**
> Symptom: instance DNS is broken (`Temporary failure in name resolution`), requiring a manual `echo nameserver 8.8.8.8 > /etc/resolv.conf`. Reason: in this image systemd-resolved's stub is not actually serving, `FallbackDNS` is ineffective, and the only reliable fix is to make `/etc/resolv.conf` a **static file**. But **`virt-customize` temporarily drops in a resolv.conf so `--run-command` can reach the network and deletes it during teardown** — anything written via it (whether `printf` or `for`) ends up empty/nonexistent. `cryptpilot-convert` also backs up the original resolv.conf → bind-mounts the host's → restores it during teardown.
> Correct approach: write it with **guestfish** (which does none of that), and do it **after all virt-customize, before convert**; convert's backup/restore preserves it:
> ```bash
> printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n' > /tmp/resolv
> guestfish --rw -a <img> <<'GF'
> run
> mount /dev/sda1 /
> rm-f /etc/resolv.conf
> upload /tmp/resolv /etc/resolv.conf
> GF
> ```

7. **Security hardening** (remove software that can bypass tapp to change the environment): `apt-get purge` Tier1/2 packages + `systemctl mask` console getty + replace netplan with MAC-independent DHCP, see **§11**.

### Stage B: base → gcp-tapp (kernel + convert + ESP)

1. **Install the gcp kernel**: `virt-customize --install linux-image-gcp,linux-modules-extra-gcp` (keep at least one `-generic`, required by convert's line-448 check)
2. **Fix A**: point the `/boot/vmlinuz`, `initrd.img` symlinks at the gcp kernel (see §5 / §7.3)
3. **DNS** (if not done in stage A, write the static resolv.conf here with guestfish)
4. **nbd reset** (convert mounts the disk with qemu-nbd; avoid leftovers / missing max_part):
   ```bash
   qemu-nbd -d /dev/nbd0; qemu-nbd -d /dev/nbd1; rmmod nbd; modprobe nbd max_part=16; partprobe /dev/nbd0
   ```
5. **convert**: `cryptpilot-convert --in <base> --out gcp-tapp.qcow2 --config-dir ./config_dir/ --rootfs-no-encryption --package cryptpilot-fde_0.7.0_amd64.deb`
   (if the caller's `TMPDIR` points at a path that does not exist inside the chroot, use `TMPDIR=/tmp`, see §7.4)
6. **Fix B**: `fix-esp-grub.sh gcp-tapp.qcow2` (sync the ESP, see §5 / §10)

### One-shot scripts

The repository provides three scripts:
- **`build-gcp-tapp.sh <bare-ubuntu.qcow2> <out.qcow2>`** — chains the full stage A + stage B flow;
- **`prepare-gcp-tapp.sh <base.qcow2> <out.qcow2>`** — stage B only (use when a base already exists); includes fix A, DNS (guestfish), nbd reset, convert, fix B;
- **`fix-esp-grub.sh <img.qcow2>`** — sync the ESP only (fix B).

```bash
# bare Ubuntu 24.04 → final gcp-tapp.qcow2 (one command)
./build-gcp-tapp.sh ubuntu-24.04.qcow2 gcp-tapp.qcow2
```
Key environment variables: `TAPP_SERVER_BIN` (local tapp-server; if empty, downloads v0.1.0), `DNS_FALLBACK`, `PURGE_KERNEL`, `CONFIG_DIR`, `FDE_PACKAGE`, `ROOTFS_MODE`, `IN_PLACE` (1 = modify the input directly without copying), `INSTALL_KERNEL`, `NBD_RESET`.

### Artifact verification checklist (all passed)

| Check | Command/method | Expected |
|---|---|---|
| gcp initrd contains cryptpilot | `lsinitrd initrd.img-*-gcp \| grep -c cryptpilot` | 16 (includes `cryptpilot-fde-before-sysroot.service`) |
| ESP default entry | `cat /EFI/ubuntu/grub.cfg` (sda15) | points to `vmlinuz-*-gcp` + `rd.neednet=1 ip=dhcp` |
| verity | `list-filesystems` | `/dev/cryptpilot/rootfs` (ext4) + `rootfs_hash` (DM_verity_hash) |
| **`/etc/resolv.conf`** | `cat` after mounting the verity LV (`vg-activate-all`) | **static file, 3 nameserver lines** (non-empty, not a symlink) |
| tapp-server | `strings tapp-server \| grep guest-components` | `…/8d71a3b` (fixed version) |
| docker/libtdx | `ls /usr/bin/dockerd /usr/lib/.../libtdx_attest.so.1` | present |

> On real TDX, also confirm: `journalctl \| grep -i rtmr` shows extend succeeded; `getent hosts github.com` resolves.

## 10. Appendix: temporary fix script `fix-esp-grub.sh`

```bash
#!/bin/bash
# Sync the latest boot-partition grub.cfg + modules to the GCP image's ESP, fixing the boot crash after switching the kernel.
# Reads/writes only the ESP (sda15) / boot (sda16), does not touch the verity rootfs; idempotent. Run it after convert.
set -euo pipefail
IMG="${1:?Usage: $0 <image.qcow2>}"
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
echo "[OK] ESP grub synced: $IMG"
```

## 11. Security hardening: remove software that can bypass tapp to change the instance environment

The goal of a confidential appliance is that "the instance's internal environment cannot be changed from outside except via tapp's measured path". The GCP Ubuntu image ships by default with many components that provide **out-of-band access / metadata-driven environment changes**, which must be removed from the base **before convert** (the rootfs becomes immutable once sealed by verity).

**Audit (derived from `dpkg` on the artifact rootfs / enumerating enabled systemd units) and disposition:**

| Tier | Component | Risk (how it bypasses tapp) | Disposition |
|---|---|---|---|
| 🔴 T1 | `openssh-server` (ssh.socket) | remote shell | purge |
| 🔴 T1 | `google-guest-agent` | inject SSH key/account from metadata, OS Login | purge |
| 🔴 T1 | `google-compute-engine` (+startup/shutdown-scripts) | run arbitrary startup/shutdown scripts from metadata (the strongest back door) | purge |
| 🔴 T1 | `google-osconfig-agent` | GCP remote package/patch/policy delivery | purge |
| 🔴 T1 | `google-compute-engine-oslogin` | OS Login (IAM → SSH) | purge |
| 🔴 T1 | `cloud-init` | create users, write files, run commands from metadata/user-data | purge |
| 🔴 T1 | `serial-getty@ttyS0` | GCP serial console login | mask |
| 🟠 T2 | `snapd` | remotely install/refresh snaps | purge + clean /snap |
| 🟠 T2 | `unattended-upgrades` | automatically change packages | purge |
| 🟠 T2 | `open-vm-tools` | hypervisor → guest operations | purge |
| 🟠 T2 | `google-cloud-ops-agent` | exfiltrate monitoring/logs | purge |
| 🟠 T2 | `pollinate` | contact an external server at boot | purge |
| 🟠 T2 | `landscape-common` / `ubuntu-pro-client` | Canonical management/subscription agent | purge |

> 🟡 T3 (assess as needed, kept for now): `cron`, `networkd-dispatcher`, `apport`, `lxd-installer.socket`, `rpcbind` / `nfs-client`, `polkitd`.
> 🟢 Kept: `tapp-server`, `docker` / `containerd` (application runtime), `systemd-networkd`, `ufw`, `rsyslog`, etc.

> **⚠️ Companion step (mandatory): after removing `cloud-init`, netplan must be replaced.**
> The GCP image's `/etc/netplan/50-cloud-init.yaml` **matches the NIC by the build-time MAC** and relies on cloud-init regenerating it for each new instance at boot. Once cloud-init is removed, a new instance's MAC changes and no longer matches → networkd ignores the NIC → **no network**. So also delete that file and replace it with MAC-independent DHCP:
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
(DNS still relies on the static `/etc/resolv.conf` from §9.)

The hardening above is integrated at the end of stage A in `build-gcp-tapp.sh` (`apt-get purge` + `systemctl mask` + netplan replacement), and is sealed into the verity measurement layer together with convert.

## 12. Extracting reference values: `show-reference-value` (requires the saved_entry fix)

After building `gcp-tapp.qcow2`, use `cryptpilot-fde` to extract the reference values needed for remote attestation (RA) **offline** from the image, and write them into the KBS/attestation policy.

### Prerequisite: cryptpilot-fde must include the §7.6 fix
A never-booted image has an empty grubenv, so the **original** `show-reference-value` reports `saved_entry not found in GRUB environment` (see §7.6). A version with the fix (openanolis/cryptpilot PR #128) is required. Before it is merged, you can build it yourself from the fork branch:
```bash
git clone -b fix/srv-default-entry https://github.com/0gfoundation/cryptpilot.git
cd cryptpilot
# build dependencies (Anolis/RHEL family):
dnf install -y device-mapper-devel clang cryptsetup-devel
LIBCLANG_PATH=/usr/lib64 cargo build --release -p cryptpilot-fde
# artifacts: target/release/cryptpilot-fde-host (host side, computes reference values offline) + cryptpilot-fde-guest (in-VM boot-service)
# note: as of 0.8.0, cryptpilot-fde is split into -host/-guest; the deployed 0.7.0 is a single cryptpilot-fde
```
> With this fix, the §7.6 "fabricate saved_entry on the convert side" workaround is **no longer needed**.

### Usage
```bash
# source-built version (0.8.0, host side):
./target/release/cryptpilot-fde-host show-reference-value --disk gcp-tapp.qcow2 --hash-algo sha384
# already-deployed 0.7.0 (single binary):
cryptpilot-fde show-reference-value --disk gcp-tapp.qcow2 --hash-algo sha384
```
- `--disk <path>`: compute offline against an image file / block device (without it, against the currently running system).
- `--hash-algo`: `sha1,sha256,sha384,sm3`, may be specified multiple times; default `sha384` (0.8.0; 0.7.0 defaults to `sha384,sm3`).
- `--stage initrd|system`: optional; `--stage system` additionally injects the `initrd_switch_root` declaration.

### Output (AAEL reference values → fed into the KBS policy)
- `AA.eventlog.cryptpilot.alibabacloud.com.load_config` — FDE config bundle hash
- `AA.eventlog.cryptpilot.alibabacloud.com.fde_rootfs_hash` — rootfs verity `root_hash`
- `AA.eventlog.cryptpilot.alibabacloud.com.initrd_switch_root` — only with `--stage system`
- SHA-384 (and the chosen algorithms) reference values for the boot components (grub / kernel / initrd / kernel cmdline)

> Ordering reminder (see §6): if you use the §7.6 convert workaround (instead of the #128 fix), `show-reference-value` must run **after** "sync the ESP (fix B)" to ensure reference value == actual boot measurement. With the #128 fix + a clean image, run it directly as above.

## 13. Persistent `/data` disk (container storage off the RAM rootfs) + Sysbox

The rootfs writable overlay is `rw_overlay = "ram"` (zram) — **anything written to `/` at runtime lives in RAM and is lost on reboot**, and is bounded by instance memory. So all persistent container state must live on a separate **`/data`** disk. `build-gcp-tapp.sh` bakes this in **unconditionally** (not tied to `ENABLE_SYSBOX`); see the gcp-cvm README for the deploy model. The non-obvious gotchas that cost real debugging:

- **fstab `/data` MUST use `nofail`.** A plain `LABEL=tapp-data /data ext4 defaults 0 2` will, when the data disk is missing or not yet labelled, fail `local-fs.target` → the whole system drops into **emergency mode → no network, no SSH** (verified: a fresh instance with a blank data disk was unreachable; serial console showed `Timed out waiting for device .../tapp-data` → `emergency.target`). Use `defaults,nofail,x-systemd.device-timeout=60s,x-systemd.requires=tapp-data-provision.service`. With `nofail`, a missing `/data` only makes docker/containerd fail-loud (`RequiresMountsFor=/data`), the OS still boots and is reachable.
- **First-boot auto-provision race.** `tapp-data-provision.service` auto-`mkfs.ext4 -L tapp-data`'s a blank non-boot disk before `data.mount`. The by-label `.device` unit's timeout must comfortably exceed the mkfs time or the mount is abandoned before the label appears (a 10s timeout lost the race on first boot; **60s** is safe — mkfs took ~4s). A *second* boot always worked because the disk was already labelled; the bug only bit the first boot.
- **Move BOTH docker `data-root` and containerd `root`.** Current docker-ce keeps image layers under **containerd's** root (`/var/lib/containerd`), which moving docker's `data-root` alone does not cover — layers would still pile onto the RAM root. Pin `data-root=/data/docker` *and* containerd `root=/data/containerd`.
- **Sysbox needs Docker ≤ 27.x.** Docker 28+/29+ emit the Linux *time namespace* in the OCI spec; `sysbox-runc` rejects it (`namespace {"time" ""} does not exist`) and container launch fails. Pin `docker-ce` to `5:27.5.1-1~ubuntu.24.04~noble` (`DOCKER_VERSION`).
- **Sysbox needs `fuse3`, not `fuse`.** `sysbox-fs` 0.7.0 uses libfuse3 and calls `fusermount3` to mount its per-container FUSE fs; with only `fuse` (fuse2) installed, container launch fails with `fusermount3: not found` / `FuseServer InitWait error`. Install `fuse3`.
- **Sysbox data store** (`sysbox-mgr --data-root`, holds inner-container images) is also moved to `/data/sysbox` via a drop-in that preserves the vendor `ExecStart`.
- **Kernel**: idmapped mounts (gcp kernel ≥5.12) are required; **6.17.0-*-gcp verified on hardware** (`docker run --runtime=sysbox-runc alpine cat /proc/self/uid_map` → `0 100000 65536`).
