# Multi-cloud TApp Confidential Image (CVM) build kit

Build a bootable, measurable, remotely-attestable, security-hardened cryptpilot TApp confidential image from a bare Ubuntu 24.04 cloud image — for **GCP** and **Alibaba Cloud**, from one set of scripts.

## Build dimensions
One CVM = one point in this grid; each combination has its own image, its own reference values, and its own AS policy.

| Dimension | Values | Set by | Effect |
|---|---|---|---|
| **boot_format** | `grub` \| `uki` | `BOOT_FORMAT` (default `grub`; `uki` is opt-in) | boot chain ⇒ **shape of the measurement** (see below) |
| **env** | `dev` (HARDEN=0) \| `prod` (HARDEN=1) | `HARDEN` | prod purges everything that can change the instance from outside; dev leaves the rest in place |
| **version** | tapp-server release tag | `TAPP_SERVER_URL` | which tapp-server binary + image-name suffix |

Not a dimension but it does change the measurement: **`DEV_SSH_PUBKEY`** (dev only) bakes an SSH
public key into a hardened image — see [Dev SSH access](#dev-ssh-access-cloud-independent).

> **Two build modes** (`BUILD_MODE`, default `canonical`):
> - **canonical** — owner-agnostic image: owner/kbs are claimed at runtime
>   (`tapp-cli claim-config`) as a measured `claim_config` event. One image and ONE
>   reference set serve every owner. Requires tapp-server ≥ v0.3.0.
> - **custom** — `OWNER_ADDRESS` baked into `config.toml` → folded into the **initrd
>   measurement** → per-owner image + per-owner reference set (legacy behaviour).

A CVM boots one way (one measurement chain). The measurement *shape* is decided by `boot_format`:
- **grub** → 5 components: `measurement.{shim,grub,kernel,initrd,kernel_cmdline}.SHA-384`
- **uki**  → 1 component:  `measurement.uki.SHA-384` (kernel+initrd+cmdline fused into one signed EFI)

> **`cloud` is not a dimension** — it only selects the Stage C publish target
> (`publish-gcp-image.sh` vs `publish-ali-image.sh`) and changes nothing in the image. One HWE
> generic kernel (≥6.16, for the TDX RTMR measurement interface) serves every platform, and the
> dev variant's SSH access is baked in at build time (`DEV_SSH_PUBKEY`) rather than injected at
> boot by a per-cloud agent — so the same build boots on GCP, Alibaba Cloud **and bare metal**
> with identical measurements. Verified on real GCP TDX hardware with `6.17.0-42-generic`.

Because they yield different images/measurements, **`boot_format` (like `env`, `version`) is part of the identifiers**, so a grub and a uki build never clobber each other:
- image name: `<imgbase>-<boot_format>-<version>` (e.g. `og-tdx-dev-grub-v0-3-0`); custom mode appends `-<owner>`
- reference value: canonical `<boot_format>/<version>/<env>.json`; custom `<boot_format>/<version>/<env>/<owner>.json`
- AS policy id: canonical `0g-tapp-<boot_format>-<version>-<env>`; custom appends `-<owner>`

Paths and policy ids from before this carried a leading `<cloud>`; they are kept, and never
written again, so nodes on those images keep verifying — see
[`verifier/reference-values/README.md`](../verifier/reference-values/README.md).

Here `<version>` is the **image** version `<tapp-server tag>[-r<image_rev>]` (`build-cvm` inputs `version` + `image_rev`; rev 1 = no suffix), **not** the binary version — the two diverge whenever the image changes and the binary does not, which is most `cvm/` changes. Rebuilding a changed image under an already-published identity re-registers new measurements behind the **same AS policy id**, and every node still running the old image stops verifying on the spot. See [docs/VERSIONING.md → CVM image](../docs/VERSIONING.md#cvm-image).

### Platform differences — only the publish step
The image is the same everywhere; `cloud` reaches nothing but Stage C.

| | GCP (`gcp`) | Alibaba Cloud (`ali`) | bare metal |
|---|---|---|---|
| kernel | HWE generic (≥6.16) | ← same | ← same |
| dev SSH access | `DEV_SSH_PUBKEY` | ← same | ← same (the only option) |
| publish | `publish-gcp-image.sh` → GCS + `gcloud compute images create` | `publish-ali-image.sh` → OSS + `aliyun ecs ImportImage` | none — boot the qcow2 with your own QEMU |

It used to differ in two more rows, and those were the whole reason `cloud` was a build
dimension: GCP got `linux-image-gcp` (the base 6.8 generic kernel lacks the TDX RTMR
measurement interface, which the HWE generic kernel supplies just as well), and each cloud got
its own key-injection agent for the dev variant (`google-guest-agent` / cloud-init pinned to
`datasource_list: [ AliYun ]`) — which is also why bare metal had no usable dev image, since it
has no metadata service to ask. `DEV_SSH_PUBKEY` replaced both.

Convert-side handling follows `BOOT_FORMAT`, not the cloud: grub syncs the ESP `grub.cfg`
(`cryptpilot-convert`, #130), `uki` runs `cryptpilot-convert --uki` (dracut + systemd-boot-efi).

## Directory contents
| File | Description |
|---|---|
| `cryptpilot-gcp-boot-fix.md` | **Main doc**: root-cause analysis + fixes + full SOP (§9) + security-hardening audit (§11) + convert issues for Alibaba Cloud (§7) |
| `build-tapp.sh` | **One-shot full chain** (cloud-generic, `CLOUD=`): base image → final tapp image (Stage A app/docker/SGX/DNS + hardening + data disk / runtime volume + Sysbox / Stage B kernel + convert / opt-in Stage C publish via `PUBLISH_AS=`) |
| `prepare-tapp.sh` | Stage B only (when a base already exists): HWE generic kernel + fix A + DNS (guestfish) + nbd reset + `cryptpilot-convert` (grub or `--uki`) |
| `run-tapp-td.sh` | **Launch the image as a TD on a bare-metal TDX host** (own QEMU, no cloud). TDX flags taken from `canonical/tdx`'s own launchers; see [`BARE_METAL.md`](BARE_METAL.md) |
| `publish-gcp-image.sh` | **Stage C (gcp)**: `qemu-img` raw → oldgnu sparse `tar.gz` → `gsutil` → `gcloud compute images create` (confidential guest-os-features). Needs gcloud/gsutil auth |
| `publish-ali-image.sh` | **Stage C (ali)**: `ossutil cp` → `aliyun ecs ImportImage` (x86_64/UEFI/QCOW2) → enable NVMe → wait Available. Needs ossutil/aliyun auth |
| `fix-esp-grub.sh` | Sync the ESP grub only (gcp/grub fix B, standalone against an already-converted image) |
| `test/boot-smoke-test.sh` | **Local boot smoke test**: boots a converted image under QEMU/OVMF (no real CVM needed) and checks the boot chain (grub *or* UKI) reaches multi-user / tapp-server |
| `config_dir/` | cryptpilot convert config (`fde.toml`, `rw_overlay="ram"`) |
| `cryptpilot-fde_0.7.0_amd64.deb` | FDE **runtime installed into the target image**. **Binary, gitignored**, must be placed locally in this directory (see Prerequisites) |

> The output qcow2 (~4–4.5G, converted / verity-sealed / hardened) is the **output** of `build-tapp.sh` and is not committed (gitignored).
> The same applies to `cryptpilot-fde_*.deb` and the tapp-server binary: the deb must be placed locally in this directory; tapp-server is pulled by default from a GitHub release (see below).

> **Running on bare metal?** The image is the same; what changes is that you launch the TD
> yourself and own the quote-generation setup. [`BARE_METAL.md`](BARE_METAL.md) is the runbook —
> verified end to end on an `ecs.ebmg8i.48xlarge`, including the one step that is genuinely easy
> to get wrong (which PCCS can serve *your* platform).

## Pipeline (stages)
- **Stage 0 — base prep** *(one-time, reused across builds & both clouds)*: official Ubuntu 24.04 cloud image → resize to 20 GiB → base qcow2. See `cryptpilot-gcp-boot-fix.md` §0. The base is **cloud-neutral** (generic kernel only). Input to Stage A, not part of `build-tapp.sh`.
- **Stage A** (`build-tapp.sh`): provision app / docker / SGX / DNS, security hardening, Sysbox, and the data disk / runtime volume + `br_netfilter` bakes. Remote-management encryption needs nothing baked: tapp-server ≥0.8.0 itself serves a TLS listener on **:50052** (per-boot in-memory self-signed cert; `[server] tls_bind_address`), so `tapp-cli --server https://<host>:50052 --insecure` is encrypted from first boot, claim included. Encryption only — defeats passive observers; against an active on-path attacker use `--tls-pin` or a CA-issued front. Node identity is established by attestation, not by that certificate.
- **Stage B** (`prepare-tapp.sh`, invoked by A): install the newest complete HWE **generic** kernel (≥6.16 — the TDX RTMR measurement interface) + fix A (point `/boot/vmlinuz` at it, so convert builds the cryptpilot initrd for the kernel grub will actually boot). Then `cryptpilot-convert` (grub, syncing the ESP) or `cryptpilot-convert --uki` per `BOOT_FORMAT`. Not cloud-dependent.
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
KBS_URLS='"http://<kbs-host-1>:9091", "http://<kbs-host-2>:9091"' \
./build-tapp.sh <bare-ubuntu-24.04.qcow2> tapp.qcow2
# One image for every platform. CLOUD (gcp|ali) is only needed for an opt-in Stage C publish
# (PUBLISH_AS=…); leave it alone to build a qcow2 you can publish later, or boot yourself.
```
- **Required**:
  - `KBS_URLS` — KBS node URLs for `[kbs] node_urls`, comma-separated and quoted as shown.
- **Build mode**: `BUILD_MODE=canonical` (default) builds an owner-agnostic image — the tapp
  boots unclaimed and owner/config are claimed at runtime via `tapp-cli claim-config`
  (measured event). `BUILD_MODE=custom` requires `OWNER_ADDRESS=0x…` and bakes it into
  `config.toml` `[server.permission]` (per-owner reference values, legacy).
- tapp-server is downloaded by default from GitHub v0.1.0 (includes the guest-components `8d71a3b4` fix, RTMR OK); if you have it locally, set `TAPP_SERVER_BIN=<path>`.
- Storage / Sysbox knobs: `DATA_ROOT` (docker data-root, default `/data/docker`, on the runtime volume), `CONTAINERD_ROOT` (default `/data/containerd`), `DOCKER_VERSION` (default `5:27.5.1-…noble`; empty = repo default), `ENABLE_SYSBOX` / `SYSBOX_VERSION` (default `0.7.0`).
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

**To make `/` bigger:** add instance **memory** (simplest — `/` grows automatically, no config change); or switch `rw_overlay` to **`disk`** so `/` is backed by the boot-disk leftover (boot-disk size then matters), still wiped each boot (stateless preserved), overlay key can be ephemeral. Use **`disk-persist`** only if `/` must survive reboots — that needs a real KBS key for the delta volume (not the placeholder currently in `fde.toml`). Persistent app data does not depend on any of this — it goes to the separate data disk (below).

## Data disk and runtime volume — always configured
The cryptpilot rootfs writable overlay is **RAM-backed (zram) and ephemeral** — anything written to `/` lives in RAM and is lost on reboot. Two kinds of data therefore need a disk, and they are kept apart:

- **The data disk** (`LABEL=tapp-data`, mounted at **`/var/lib/tapp/disk`**, used only by tapp-server) holds **only what must persist**: each app's volume (`tapp/volumes/<app>.img`, encrypted with a KMS-derived key) or plain directory (`tapp/plain/<app>`), per `x-tapp.data` — named volumes are redirected into them. Nothing else: tapp-server refuses an app that mounts the disk writable.
- **`/data` is the runtime volume**, which `tapp-runtime-volume.service` creates at every boot from a sparse file on the data disk, `tapp/runtime.img`, encrypted (plain dm-crypt, AES-256-XTS) with a key read from the kernel RNG and held only in the kernel. docker's `data-root` and containerd's `root` (which holds the image layers in current docker-ce) are `/data/docker` and `/data/containerd`, tapp-server's logs are `/data/log/tapp`, and anything an app bind-mounts from an absolute `/data/...` path lands there too. All of it is secret, cannot be altered from outside the TEE before the next start, and is **empty after every reboot** — a previous boot's containers cannot come back, and images are pulled again by the next `start-app`. Discards are passed down, so deleting images frees disk space. `DATA_ROOT` / `CONTAINERD_ROOT` move the container stores; pointing them at the data disk would put all of that back on a plain, persistent disk.
- The runtime volume is created only when `/var/lib/tapp/disk` is the `tapp-data` disk and `/data` is not already a mount; it touches nothing on the disk but its own file, and is kept if the unit restarts within a boot. On a disk carried over from an older image (where it was mounted at `/data`) it also removes, once, the container storage that image left there in the clear — `docker/`, `containerd/`, `sysbox/` — and nothing else. `docker.service` + `containerd.service` **require** it → they **fail loud** (won't start) without it, never writing to the RAM root or to the data disk in the clear. tapp-server (≥0.9.1) likewise refuses to create an app volume unless the data disk is mounted.
- fstab mounts `LABEL=tapp-data` at `/var/lib/tapp/disk` with **`nofail`** (+ `x-systemd.device-timeout=60s`). A missing/blank data disk therefore does **not** brick boot — without `nofail` a failed mount drops the whole system into **emergency mode → no SSH**; with it, only tapp-server and docker/containerd stay down.

**Two-disk deploy model:**
- **Boot disk = the image size (~20 GB). Do not oversize it.** The writable layer is RAM (zram, bounded by *instance memory*) and the rootfs is read-only verity, so extra boot-disk space is unreachable and wasted. Want more writable capacity on `/` → give the instance more **RAM**, not a bigger boot disk; container storage is on the data disk, through the runtime volume.
- **Attach one persistent disk as the data disk** (any size; detach / snapshot / migrate it independently). **No manual formatting or labelling needed** — on first boot `tapp-data-provision.service` finds the single non-boot disk and:
  - **blank disk** → `mkfs.ext4 -L tapp-data`, mount, then **auto-grow** (`resize2fs`) to fill it (fresh node);
  - **disk that already has an ext4 filesystem** (e.g. a migrated chain-data disk, or one from an image of the older layout) → **adopted as-is** (`e2label tapp-data`, **never reformatted** — data preserved), then mounted.

  Safe: only real disks (`sd*`/`nvme*`/`vd*`), never the boot disk, never a partitioned disk; with zero or more-than-one candidate it refuses to guess (the disk stays unmounted → tapp-server and docker fail loud). So *attach any single data disk — brand-new or carrying data — and it is used, no SSH, no reboot, no `mkfs`/`e2label`.* A disk already labelled `tapp-data` short-circuits.
- **The data disk itself is plain ext4.** What is protected on it from the cloud operator is what is encrypted inside it: the apps' encrypted volumes and the runtime volume. Only a `plain` app's data is not — that app's own choice. tapp-server's logs are on the runtime volume, so after a reboot the node has none from the previous boot.

## Multi-tenant container isolation — Sysbox (issue #21, opt-in)
For hostile-multi-tenant workloads (e.g. 0g-sandbox), build with `ENABLE_SYSBOX=1` to install [Sysbox](https://github.com/nestybox/sysbox) and register `sysbox-runc` as a dockerd runtime, so in-container `root` is user-namespace-remapped (a kernel CVE in a sandbox is no longer host-equivalent):
```bash
ENABLE_SYSBOX=1 KBS_URLS='...' ./build-tapp.sh base.qcow2 gcp-tapp.qcow2
```
- Only the runtime registration is gated behind `ENABLE_SYSBOX`; the runtime volume above is there regardless. Sysbox's own data store is on it too: `sysbox-mgr --data-root` → **`/data/sysbox`** (it holds inner-container images).
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

**In CI, reach both clouds from one build: `cloud=both`.** The image is identical on every platform,
so building twice to publish twice was waste — and the second dispatch also redid the identity work,
pushing the same `refvalues/*` branch and failing there, which marked a good dual-publish red. With
`cloud=both` one build is published to GCP and Alibaba Cloud while the reference values, the AS
policy and the refvalues PR are produced once, as they should be for one image. `gcp` and `ali`
remain if you want a single target. For a GPU build, which spends most of its 90 minutes in DKMS,
this is the difference between one build and two.

## Three core fixes (all required)
- **Fix A**: before convert, point the `/boot/vmlinuz` symlink at the gcp kernel → the cryptpilot stack goes into the correct initrd (fixes read-only / RTMR / verity).
- **Fix B**: after convert, sync the boot-partition grub.cfg + modules to the ESP (fixes the boot crash bli.mod / vmlinuz not found).
- **Application side (§8)**: tapp-server uses guest-components `8d71a3b4` (already in v0.1.0) → RTMR extend no longer misdetected.
- Also: DNS must be written to a static `/etc/resolv.conf` with **guestfish** (virt-customize wipes what it writes itself); reset nbd before convert with `modprobe nbd max_part=16`.

## Security hardening (integrated in build stage A, see doc §11)
purge: openssh-server / cloud-init / snapd / google-guest-agent / google-compute-engine (+oslogin) / google-osconfig-agent / google-cloud-ops-agent / open-vm-tools / pollinate / landscape-common; mask the serial/local getty; switch netplan to MAC-independent DHCP.

### No unattended apt changes, both variants (issue #71) — applied unconditionally, dev images too
Stage A always:
- purges `unattended-upgrades` and **masks** `apt-daily{,-upgrade}.{timer,service}` (masking the timers matters on its own: they ship with `apt`, not with unattended-upgrades);
- zeroes every `APT::Periodic::*` knob in `/etc/apt/apt.conf.d/20auto-upgrades`;
- sets needrestart to **list-only** (`$nrconf{restart} = 'l'`, drop-in `99-tapp-no-auto-restart.conf` — the name must sort **last**, needrestart reads `conf.d/*.conf` sorted and the last assignment wins), so even a manual `apt install` never restarts a service by itself.

Why it is a build-time hard gate (`cvm/ci/check-no-auto-update.sh`, run on the final image in `build-cvm.yml`): an auto-upgrade restarts tapp-server — observed on testnet as a glibc upgrade restarting `tapp-server` + `containerd` + `sysbox` in one go — and tapp derives the app signer in memory, so **within that same boot** every on-chain node/service of every app on the node silently goes stale. (On an image variant whose `/boot`/ESP is writable at runtime, an auto kernel upgrade would additionally change RTMR + `kernel_cmdline` and invalidate the reference values; here the rootfs overlay is RAM-backed, so that one is the secondary concern.) Package updates go through a rebuild, which regenerates reference values, never through the running node.

Scope: this covers **apt**. `HARDEN=1` additionally purges the other self-changing components (`snapd` auto-refresh, `ubuntu-pro-client`'s `ua-timer`/`apt-news`/`esm-cache`, `motd-news`); on a `HARDEN=0` dev image those are still present.

<a name="dev-ssh-access-cloud-independent"></a>
### Dev SSH access without a cloud — `DEV_SSH_PUBKEY` (dev only)
The `HARDEN=0` dev variants get you in by letting the **cloud inject your key at boot**: on GCP
`google-guest-agent` reads it from `metadata.google.internal`, on Alibaba Cloud cloud-init reads it
from `100.100.100.200`. That is why the dev image has to pick a cloud — and why **neither dev
variant can be used on bare metal**, where no metadata service exists at all and a self-launched TD
is handed nothing.

`DEV_SSH_PUBKEY` removes the dependency by baking the key at **build** time, so nothing has to be
asked for at boot:

```bash
DEV_SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" CLOUD=ali BOOT_FORMAT=uki HARDEN=1 \
  ./build-tapp.sh base-noble.qcow2 out-dev.qcow2      # then: ssh root@<ip>
```

or the `dev_ssh_pubkey` input on `build-cvm`. Unset ⇒ the block is skipped and the image is
byte-identical, so this is inert on every normal build. It reinstalls the `openssh-server` that
`HARDEN=1` purges, writes `/root/.ssh/authorized_keys`, and unmasks the getty.

On `build-cvm` the key is **ignored for the prod image, with a warning** (log annotation + run
summary) rather than rejected up front, so `env=both` stays usable — one dispatch gives a keyed dev
image and a clean prod one. A **malformed** key is still a hard failure in `Validate inputs`
whatever the env: it is always a typo, and it would otherwise build a dev image whose
`authorized_keys` grants nothing, discovered only when the login fails.

One image then works on GCP, Alibaba Cloud **and** bare metal — bare metal being the one where it is
the *only* option, see below. Prefer baking a *team's* keys over one person's: the key is measured,
so rotating it means rebuilding.

**On a hardened image the cloud's own entry points stay dead.** `gcloud compute ssh` and GCP's
browser SSH both work by pushing an ephemeral key to instance metadata for `google-guest-agent` to
install, and `HARDEN=1` purges that agent — verified on a hardened image as
`Permission denied (publickey)`. Alibaba Cloud's console "remote connect" fails for the same
reason. There, your baked key is the only way in, and
`gcloud compute instances get-serial-port-output` (hypervisor-level, so it needs nothing in the
guest) the only fallback.

One difference between the variants is worth stating plainly, because "no way in" is easy to
read as "nothing listening". **A dev image runs sshd; a prod image does not** — unless it was
built with `DEV_SSH_PUBKEY`, which reinstalls `openssh-server` (CI forces the key empty for
prod). `HARDEN=1` purges `openssh-server` outright (it heads the purge list), while `HARDEN=0`
leaves the base image's copy in place. Measured on v0.8.0-r2 instances: port 22 answers on the
dev image, refuses on the prod one. Whether a keyless dev image's sshd has any key to accept is
the next question, and the answer depends on the platform:

**A dev image keeps cloud-init, and whether that is a way in depends on the platform.** Only
`HARDEN=1` purges cloud-init; `HARDEN=0` keeps it and does not pin its datasource, so
ds-identify still detects the platform and could in principle inject the project's SSH key from
instance metadata. Whether it actually can turns on one detail — how that platform's metadata
endpoint is addressed — and the answer measured so far is not uniform:

| platform | metadata endpoint | keyless dev image |
|---|---|---|
| GCP | `metadata.google.internal` (a **name**) | **closed, measured** |
| Alibaba Cloud | `100.100.100.200` (an **IP**) | **unmeasured, assume open** |
| bare metal | none | closed |

On GCP it is closed, and not by design: the image writes a static `/etc/resolv.conf` (fix C in
`prepare-tapp.sh`), which cannot resolve an internal name, so cloud-init falls through to
`DataSourceNone` and injects nothing. Measured on a TDX instance —

```
DataSourceGCE.py[WARNING]: address "http://metadata.google.internal/computeMetadata/v1/" is not resolvable
Datasource DataSourceNone.  Used fallback datasource
ci-info: no authorized SSH keys fingerprints found for user ubuntu
```

`sshd` runs and port 22 answers; there is simply no key. The same reasoning does **not** carry to
Alibaba Cloud, whose endpoint is a literal IP and needs no resolution, so the static
`resolv.conf` does nothing to it and key injection is plausible. That has not been measured —
treat an Aliyun keyless dev image as reachable by the project's keys until someone checks, and
pin the datasource to `None` if you need it closed.

On **bare metal** there is no metadata service to ask on any platform, which is the gap
`DEV_SSH_PUBKEY` closes unconditionally.

That is the trade, and it is the point: the cloud's convenience *is* its ability to inject
credentials into your instance, which is exactly what hardening removes. In exchange, **who can get
in becomes part of the measurement** — the key lands in the verity-sealed rootfs, whose root hash is
in the initrd, which is in the UKI. Measured on real TDX hardware, the same image with and without a
baked key:

| image | `measurement.uki.SHA-384` |
|---|---|
| hardened, no key | `335c28e6971fc1ef…` |
| hardened + baked key | `b0a640cae384ddde…` |

So a keyed dev image has its own reference values and **cannot be mistaken for a production one** by
any verifier. It is still a deliberate back door: never publish one as a production image.

**A keyed image needs its own `image_rev`.** The key changes the measurement but appears in no
identifier — not the image name, the reference-value path, the AS policy id, nor the concurrency
group. So building one under an identity that already has reference values would replace what
every node of that identity verifies against. `build-cvm` now refuses that (see
`allow_refval_overwrite`), but the fix is to bump `image_rev`, not to override the guard.

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
