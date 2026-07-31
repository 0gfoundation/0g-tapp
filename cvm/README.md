# Multi-cloud TApp Confidential Image (CVM) build kit

Build a bootable, measurable, remotely-attestable, security-hardened cryptpilot TApp confidential image from a bare Ubuntu 24.04 cloud image — for **GCP** and **Alibaba Cloud**, from one set of scripts.

## Build dimensions
One CVM = one point in this grid; each combination has its own image, its own reference values, and its own AS policy.

| Dimension | Values | Set by | Effect |
|---|---|---|---|
| **cloud** | `gcp` \| `ali` | `CLOUD` | kernel + guest agent + publish target (see platform table) |
| **boot_format** | `grub` \| `uki` | `BOOT_FORMAT` (default `grub` for any cloud; `uki` is opt-in) | boot chain ⇒ **shape of the measurement** (see below) |
| **env** | `dev` (HARDEN=0) \| `prod` (HARDEN=1) | `HARDEN` | dev keeps cloud-init/SSH for debugging; prod purges it |
| **version** | tapp-server release tag | `TAPP_SERVER_URL` | which tapp-server binary + image-name suffix |

> **Two build modes** (`BUILD_MODE`, default `canonical`):
> - **canonical** — owner-agnostic image: owner/chain/kbs are claimed at runtime
>   (`tapp-cli claim-config`) as a measured `claim_config` event. One image and ONE
>   reference set serve every owner. Requires tapp-server ≥ v0.3.0.
> - **custom** — `OWNER_ADDRESS` baked into `config.toml` → folded into the **initrd
>   measurement** → per-owner image + per-owner reference set (legacy behaviour).

`cloud` and `boot_format` are **independent axes** — a CVM boots one way (one measurement chain), regardless of cloud. The measurement *shape* is decided by `boot_format`, not cloud:
- **grub** → 5 components: `measurement.{shim,grub,kernel,initrd,kernel_cmdline}.SHA-384`
- **uki**  → 1 component:  `measurement.uki.SHA-384` (kernel+initrd+cmdline fused into one signed EFI)

Because they yield different images/measurements, **`boot_format` (like `cloud`, `env`, `version`) is part of the identifiers**, so a grub and a uki build never clobber each other:
- image name: `<imgbase>-<boot_format>-<version>` (e.g. `og-tdx-dev-grub-v0-3-0`); custom mode appends `-<owner>`
- reference value: canonical `…/<version>/<env>.json`; custom `…/<version>/<env>/<owner>.json`
- AS policy id: canonical `0g-tapp-<cloud>-<boot_format>-<version>-<env>`; custom appends `-<owner>`

### Platform differences (everything else is shared)
| | GCP (`gcp`) | Alibaba Cloud (`ali`) |
|---|---|---|
| default boot format | grub | grub (`uki` opt-in via `BOOT_FORMAT=uki`) |
| kernel | `linux-image-gcp` (+ fix A: point `/boot/vmlinuz`) | base **generic** kernel (ECS uses virtio; no swap) |
| guest / dev SSH inject | `google-guest-agent` | cloud-init pinned to `datasource_list: [ AliYun ]` |
| convert boot handling | grub → ESP grub.cfg sync (`cryptpilot-convert`, #130) | grub → ESP sync; `uki` → `cryptpilot-convert --uki` (dracut + systemd-boot-efi) |
| publish | `publish-gcp-image.sh` → GCS + `gcloud compute images create` | `publish-ali-image.sh` → OSS + `aliyun ecs ImportImage` |

## Directory contents
| File | Description |
|---|---|
| `cryptpilot-gcp-boot-fix.md` | **Main doc**: root-cause analysis + fixes + full SOP (§9) + security-hardening audit (§11) + convert issues for Alibaba Cloud (§7) |
| `build-tapp.sh` | **One-shot full chain** (cloud-generic, `CLOUD=`): base image → final tapp image (Stage A app/docker/SGX/DNS + hardening + /data + Sysbox / Stage B kernel + convert / opt-in Stage C publish via `PUBLISH_AS=`) |
| `prepare-tapp.sh` | Stage B only (when a base already exists): fix A (gcp) / generic kernel (ali) + DNS (guestfish) + nbd reset + `cryptpilot-convert` (grub or `--uki`) |
| `publish-gcp-image.sh` | **Stage C (gcp)**: `qemu-img` raw → oldgnu sparse `tar.gz` → `gsutil` → `gcloud compute images create` (confidential guest-os-features). Needs gcloud/gsutil auth |
| `publish-ali-image.sh` | **Stage C (ali)**: `ossutil cp` → `aliyun ecs ImportImage` (x86_64/UEFI/QCOW2) → enable NVMe → wait Available. Needs ossutil/aliyun auth |
| `fix-esp-grub.sh` | Sync the ESP grub only (gcp/grub fix B, standalone against an already-converted image) |
| `test/boot-smoke-test.sh` | **Local boot smoke test**: boots a converted image under QEMU/OVMF (no real CVM needed) and checks the boot chain (grub *or* UKI) reaches multi-user / tapp-server |
| `config_dir/` | cryptpilot convert config (`fde.toml`, `rw_overlay="ram"`) |
| `cryptpilot-fde_0.7.0_amd64.deb` | FDE **runtime installed into the target image**. **Binary, gitignored**, must be placed locally in this directory (see Prerequisites) |

> The output qcow2 (~4–4.5G, converted / verity-sealed / hardened) is the **output** of `build-tapp.sh` and is not committed (gitignored).
> The same applies to `cryptpilot-fde_*.deb` and the tapp-server binary: the deb must be placed locally in this directory; tapp-server is pulled by default from a GitHub release (see below).

## Pipeline (stages)
- **Stage 0 — base prep** *(one-time, reused across builds & both clouds)*: official Ubuntu 24.04 cloud image → resize to 20 GiB → base qcow2. See `cryptpilot-gcp-boot-fix.md` §0. The base is **cloud-neutral** (generic kernel only). Input to Stage A, not part of `build-tapp.sh`.
- **Stage A** (`build-tapp.sh`): provision app / docker / SGX / DNS, security hardening, Sysbox, and the `/data` + `br_netfilter` bakes.
- **Stage B** (`prepare-tapp.sh`, invoked by A): `CLOUD=gcp` → install the gcp kernel + fix A; `CLOUD=ali` → keep the generic kernel. Then `cryptpilot-convert` (grub, syncing the ESP) or `cryptpilot-convert --uki` per `BOOT_FORMAT`.
- *(optional)* local boot smoke test (`test/boot-smoke-test.sh`).
- **Stage C** (`publish-gcp-image.sh` / `publish-ali-image.sh` by `CLOUD`): publish the built qcow2 to the cloud. Run standalone, or from `build-tapp.sh` via `PUBLISH_AS=<name>`.

## Prerequisites
- **Conversion host = Anolis / Alibaba Cloud Linux 3 (al8).** `cryptpilot-convert` is only packaged for al8; a plain Ubuntu/macOS host cannot run it.
- Install the host tool and dependencies (run the build as **root**):
  ```bash
  # cryptpilot-convert (host tool), from openanolis/cryptpilot v0.7.0 release:
  #   https://github.com/openanolis/cryptpilot/releases/tag/v0.7.0
  sudo rpm -i cryptpilot-fde-0.7.0-1.al8.x86_64.rpm     # provides /usr/bin/cryptpilot-convert
  sudo dnf install -y libguestfs-tools qemu-img          # guestfish, virt-customize, qemu-img, qemu-nbd
  sudo modprobe nbd max_part=16
  export LIBGUESTFS_BACKEND=direct
  # docker is only needed for test/boot-smoke-test.sh
  ```
- Place into this directory (gitignored binaries):
  - `cryptpilot-fde_0.7.0_amd64.deb` — the FDE runtime for the **target image**, from the same [v0.7.0 release](https://github.com/openanolis/cryptpilot/releases/tag/v0.7.0) (the `.deb`, distinct from the host `.al8.rpm`).
  - `tapp-server` is optional locally — pulled from the 0g-tapp v0.1.0 release by default, or set `TAPP_SERVER_BIN=<path>`.

See `cryptpilot-gcp-boot-fix.md` §0.1 for details.

## One-shot build
```bash
export LIBGUESTFS_BACKEND=direct
CLOUD=gcp \                       # or CLOUD=ali (default gcp; picks kernel/guest/boot-format/publish)
KBS_URLS='"http://<kbs-host-1>:9091", "http://<kbs-host-2>:9091"' \
./build-tapp.sh <bare-ubuntu-24.04.qcow2> tapp.qcow2
```
- **Required**:
  - `KBS_URLS` — KBS node URLs for `[kbs] node_urls`, comma-separated and quoted as shown.
- **Build mode**: `BUILD_MODE=canonical` (default) builds an owner-agnostic image — the tapp
  boots unclaimed and owner/config are claimed at runtime via `tapp-cli claim-config`
  (measured event). `BUILD_MODE=custom` requires `OWNER_ADDRESS=0x…` and bakes it into
  `config.toml` `[server.permission]` (per-owner reference values, legacy).
- tapp-server is downloaded by default from GitHub v0.1.0 (includes the guest-components `8d71a3b4` fix, RTMR OK); if you have it locally, set `TAPP_SERVER_BIN=<path>`.
- Storage / Sysbox knobs: `DATA_ROOT` (docker data-root, default `/data/docker`), `CONTAINERD_ROOT` (default `/data/containerd`), `DOCKER_VERSION` (default `5:27.5.1-…noble`; empty = repo default), `ENABLE_SYSBOX` / `SYSBOX_VERSION` (default `0.7.0`).
- Publish (Stage C, opt-in): `PUBLISH_AS=<gcp-image-name>` publishes the built image to GCP after the build (see [Publish to GCP](#publish-to-gcp-stage-c)); `GCS_BUCKET` / `GCP_PROJECT` / `GUEST_OS_FEATURES` pass through.
- Other environment variables: `DNS_FALLBACK` `PURGE_KERNEL` `CONFIG_DIR` `FDE_PACKAGE` `ROOTFS_MODE` `IN_PLACE` `INSTALL_KERNEL` `NBD_RESET` (see the top of the script).

## Root filesystem size (`/`) — read-only base + writable overlay
`/` is **assembled at boot** by `cryptpilot-fde` (not a fixed partition), stacking two parts:
- **read-only base** — your image's actual content, sealed under dm-verity. `cryptpilot-convert` shrinks the rootfs to the real data size (~4 GiB for a bare build), so this part is **fixed by what you bake in**, independent of the disk size (growing the input disk does *not* grow it).
- **writable overlay** — a copy-on-write layer on top. Where it lives is set by **`rw_overlay`** in `config_dir/fde.toml` (cryptpilot's `delta_location`):

| `rw_overlay` | overlay backed by | survives reboot? | size |
|---|---|---|---|
| `ram` *(what we ship)* | memory (a `zram` device) | no (wiped) | `= MemTotal` (≈ instance RAM, minus kernel reserve) |
| `disk` *(cryptpilot default)* | boot-disk leftover (LVM delta LV, LUKS2) | no (wiped each boot) | = leftover disk |
| `disk-persist` | same, but retained | **yes** | = leftover disk |

Apparent `/` size (`df`) = **read-only base + overlay size**. Under our `rw_overlay = "ram"`:
- `/` ≈ (baked data ~4 GiB) + (total RAM). **Measured: a 16 GiB-RAM instance → ~18.7 GiB `/`** (≈4 + ~14.7); a 64 GiB-RAM instance → ~66 GiB.
- **The boot disk does not affect `/`** — nothing reads it for the root. A bigger boot disk is wasted; keep it ≈ the image size.
- That writable space **is RAM**: bytes written to `/` consume (compressed) memory shared with the workload, and are **lost on reboot**. It's a ceiling competing with app memory, not free disk.

**To make `/` bigger:** add instance **memory** (simplest — `/` grows automatically, no config change); or switch `rw_overlay` to **`disk`** so `/` is backed by the boot-disk leftover (boot-disk size then matters), still wiped each boot (stateless preserved), overlay key can be ephemeral. Use **`disk-persist`** only if `/` must survive reboots — that needs a real KBS key for the delta volume (not the placeholder currently in `fde.toml`). Persistent app data does not depend on any of this — it goes to the separate `/data` disk (below).

## Persistent data disk (`/data`) — always configured
The cryptpilot rootfs writable overlay is **RAM-backed (zram) and ephemeral** — anything written to `/` lives in RAM and is lost on reboot. So all persistent container state is pinned off the root onto a separate **`/data`** disk. This is **unconditional** (independent of Sysbox); every image does it:

- **docker `data-root` → `/data/docker`** *and* **containerd `root` → `/data/containerd`** — both, because current docker-ce keeps image layers under containerd's root, which moving `data-root` alone does **not** cover. Configurable via `DATA_ROOT` / `CONTAINERD_ROOT`.
- `docker.service` + `containerd.service` get `RequiresMountsFor=/data` → they **fail loud** (won't start) if `/data` is missing, never silently writing to the RAM root.
- fstab mounts `LABEL=tapp-data` at `/data` with **`nofail`** (+ `x-systemd.device-timeout=60s`). A missing/blank data disk therefore does **not** brick boot — without `nofail` a failed `/data` mount drops the whole system into **emergency mode → no SSH**; with it, only docker/containerd stay down.

**Two-disk deploy model:**
- **Boot disk = the image size (~20 GB). Do not oversize it.** The writable layer is RAM (zram, bounded by *instance memory*) and the rootfs is read-only verity, so extra boot-disk space is unreachable and wasted. Want more writable capacity → give the instance more **RAM**, not a bigger boot disk.
- **Attach one persistent disk for `/data`** (any size; detach / snapshot / migrate it independently). **No manual formatting or labelling needed** — on first boot `tapp-data-provision.service` finds the single non-boot disk and:
  - **blank disk** → `mkfs.ext4 -L tapp-data`, mount, then **auto-grow** (`resize2fs`) to fill it (fresh node);
  - **disk that already has an ext4 filesystem** (e.g. a migrated chain-data disk) → **adopted as-is** (`e2label tapp-data`, **never reformatted** — data preserved), then mounted.

  Safe: only real disks (`sd*`/`nvme*`/`vd*`), never the boot disk, never a partitioned disk; with zero or more-than-one candidate it refuses to guess (`/data` stays unmounted → docker fails loud). So *attach any single data disk — brand-new or carrying data — and it becomes `/data`, no SSH, no reboot, no `mkfs`/`e2label`.* A disk already labelled `tapp-data` short-circuits.
- **`/data` confidentiality is Phase 2.** Today `/data` is plaintext ext4 relying on GCP's default at-rest encryption (Google-managed keys), which does **not** protect against the cloud operator. Phase 2 binds it to a KBS/attestation key (mount-layer dm-crypt, no image change). Do not treat Phase 1 `/data` as confidential vs the host.

## Multi-tenant container isolation — Sysbox (issue #21, opt-in)
For hostile-multi-tenant workloads (e.g. 0g-sandbox), build with `ENABLE_SYSBOX=1` to install [Sysbox](https://github.com/nestybox/sysbox) and register `sysbox-runc` as a dockerd runtime, so in-container `root` is user-namespace-remapped (a kernel CVE in a sandbox is no longer host-equivalent):
```bash
ENABLE_SYSBOX=1 KBS_URLS='...' ./build-tapp.sh base.qcow2 gcp-tapp.qcow2
```
- Only the runtime registration is gated behind `ENABLE_SYSBOX`; the `/data` storage pinning above happens regardless. Sysbox's own data store is also moved off the RAM root: `sysbox-mgr --data-root` → **`/data/sysbox`** (it holds inner-container images).
- **Docker is pinned to 27.5.1** (`DOCKER_VERSION`). Docker 28+/29+ emit the Linux *time namespace* in the OCI spec, which `sysbox-runc` rejects (`namespace ... does not exist`); Nestybox supports Docker 20.10–27.x only.
- The image ships **`fuse3`** (`fusermount3`), which `sysbox-fs` 0.7.0 needs to mount its per-container FUSE fs (without it container launch fails with `FuseServer InitWait`).
- **`br_netfilter`** is auto-loaded (`/etc/modules-load.d/`, baked for **all** images). Docker 28's `icc=false` bridges — created by the 0g-sandbox runner — hard-require `/proc/sys/net/bridge/bridge-nf-call-iptables`, which only exists once `br_netfilter` is loaded; a fresh CVM without it crash-loops the runner.
- **Kernel**: the gcp kernel (≥5.12, idmapped mounts) is supported (**6.17 verified on hardware**); the alinux 5.10 image is not (would need shiftfs).
- **Validate on hardware**: `docker run --rm --runtime=sysbox-runc alpine cat /proc/self/uid_map` should show a remapped range (e.g. `0 100000 65536`). Static build-side check: `CHECK_SYSBOX=1 ./test/boot-smoke-test.sh <img>`.
- **Measurement**: enabling Sysbox changes the rootfs/initrd measurements → regenerate reference values (see #19).

## Local boot smoke test
Before uploading an image to GCP, sanity-check that it actually boots, locally, without a real Confidential VM:
```bash
./test/boot-smoke-test.sh gcp-tapp.qcow2
```
It boots the image under QEMU/OVMF (UEFI) in the `qemux/qemu` container — using `/dev/kvm` if present, otherwise TCG software emulation — and scans the serial console for the full chain: grub → gcp kernel → `cryptpilot-fde` (dm-verity + zram + dm-snapshot) → `/sysroot` mount → switch-root → multi-user / `tapp-server.service`. Exit code `0` means the boot was confirmed.

This validates everything except the TDX-specific bits (RTMR extend, remote attestation), which require real hardware — so it is a fast pre-flight check, not a replacement for on-hardware testing. Tunables: `MAX` (timeout seconds), `RAM_SIZE`, `CPU_CORES`.

<a name="publish-to-gcp-stage-c"></a>
## Publish to GCP (Stage C)
A qcow2 can't be uploaded to GCP directly — it must become a `disk.raw` inside a sparse `oldgnu` tarball, then a GCP image. `publish-gcp-image.sh` does the four steps (`qemu-img convert` → `tar --format=oldgnu -Szcf` → `gsutil cp` → `gcloud compute images create` with `UEFI_COMPATIBLE,GVNIC,SEV_CAPABLE,TDX_CAPABLE`):
```bash
gcloud auth login            # gcloud + gsutil must be authenticated with write access to the bucket/project
./publish-gcp-image.sh /path/og-tdx-dev.qcow2 og-tdx-dev
./publish-gcp-image.sh /path/og-tdx.qcow2     og-tdx
```
Defaults `GCS_BUCKET=gs://tapp-image`, `GCP_PROJECT=g-devops`, `GUEST_OS_FEATURES=UEFI_COMPATIBLE,GVNIC,SEV_CAPABLE,TDX_CAPABLE` (all overridable). It refuses to clobber an existing image name (delete it, or publish under a new name). Or fold it into the build as an opt-in final stage:
```bash
PUBLISH_AS=og-tdx-dev ENABLE_SYSBOX=1 KBS_URLS='...' ./build-tapp.sh base.qcow2 og-tdx-dev.qcow2
```
Create a confidential instance from the published image with `--image=<name> --image-project=g-devops --confidential-compute-type=TDX`.

## Publish to Alibaba Cloud (Stage C, `CLOUD=ali`)
A qcow2 can't be registered directly — it goes through OSS. `publish-ali-image.sh` does four steps (`ossutil cp` → `aliyun ecs ImportImage` → enable NVMe → wait `Available`), pinning the four params that are easy to get wrong per the Ali confidential-disk guide: **Architecture=x86_64, BootMode=UEFI, Format=QCOW2, and NVMe support enabled *after* import**:
```bash
# ossutil + aliyun both authenticated (AK/SK env, or an instance RAM role on an Ali ECS build host)
ALIYUN_REGION=cn-beijing ./publish-ali-image.sh /path/og-tdx-ali-dev.qcow2 og-tdx-ali-dev
```
Defaults `OSS_BUCKET=0g-confidential-disk` (`ALIYUN_REGION` required, no default). It refuses to clobber an existing image name. In CI the al8 build runner is itself an Ali ECS instance, so it authenticates via its **instance RAM role** (no AK/SK secret). Create a confidential (TDX) instance from the image; assign a public IPv4 (for Trustee attestation) and use **key-pair** auth (passwords are unsupported on confidential instances).

## Three core fixes (all required)
- **Fix A**: before convert, point the `/boot/vmlinuz` symlink at the gcp kernel → the cryptpilot stack goes into the correct initrd (fixes read-only / RTMR / verity).
- **Fix B**: after convert, sync the boot-partition grub.cfg + modules to the ESP (fixes the boot crash bli.mod / vmlinuz not found).
- **Application side (§8)**: tapp-server uses guest-components `8d71a3b4` (already in v0.1.0) → RTMR extend no longer misdetected.
- Also: DNS must be written to a static `/etc/resolv.conf` with **guestfish** (virt-customize wipes what it writes itself); reset nbd before convert with `modprobe nbd max_part=16`.

## Security hardening (integrated in build stage A, see doc §11)
purge: openssh-server / cloud-init / snapd / google-guest-agent / google-compute-engine (+oslogin) / google-osconfig-agent / google-cloud-ops-agent / open-vm-tools / pollinate / landscape-common; mask the serial/local getty; switch netplan to MAC-independent DHCP.

### No self-updating, both variants (issue #71) — applied unconditionally, dev images too
A measured image must only change when an operator changes it, so stage A always:
- purges `unattended-upgrades` and **masks** `apt-daily{,-upgrade}.{timer,service}` (masking the timers matters on its own: they ship with `apt`, not with unattended-upgrades);
- zeroes every `APT::Periodic::*` knob in `/etc/apt/apt.conf.d/20auto-upgrades`;
- sets needrestart to **list-only** (`$nrconf{restart} = 'l'`), so even a manual `apt install` never restarts a service by itself.

Why it is a build-time hard gate (`cvm/ci/check-no-auto-update.sh`, run on the final image in `build-cvm.yml`): an auto-upgrade restarts tapp-server → the in-memory app signer is re-derived → every on-chain node/service of every app on that node silently goes stale; and an auto kernel/initrd upgrade changes RTMR + `kernel_cmdline` → the image's whole reference-value set is invalidated. Both surface days later, far from the build. Package updates go through a rebuild (which regenerates reference values), never through the running node.

## Verification (passed)
- Image static checks: all the above packages gone, getty masked, netplan = 01-dhcp, resolv.conf 3 lines, gcp initrd cryptpilot = 16.
- Runtime (real TDX): SSH unreachable; app starts normally via tapp + measurement + RA.
- Authoritative check of the internal listening surface: `ss -tlnp` inside the instance (with no login entry after lockdown, use a boot-time audit service that outputs to the serial console, see the same-named suggestion in the doc).

## Extracting reference values (for remote attestation)
After building, use a `cryptpilot-fde` with the fix (openanolis/cryptpilot#128) to extract RA reference values offline from the image:
```bash
cryptpilot-fde show-reference-value --disk gcp-tapp.qcow2 --hash-algo sha384
```
The original version reports `saved_entry not found` because a new image's grubenv is empty; see the main doc **§12** (includes the steps to build a fixed cryptpilot-fde from the fork branch).

## TODO (optional, "zero-residue" finishing, non-blocking)
- Remove leftover `authorized_keys` (root + 4 human accounts) + lock/delete human accounts;
- Clean up Tier3: `rpcbind` (listening on 111) / `lxd-installer.socket`, etc.
