# GCP TApp Confidential Image (CVM) build kit

Build a bootable, measurable, remotely-attestable, security-hardened cryptpilot TApp confidential image from a bare Ubuntu 24.04 cloud image.

## Directory contents
| File | Description |
|---|---|
| `cryptpilot-gcp-boot-fix.md` | **Main doc**: root-cause analysis + fixes + full SOP (§9) + security-hardening audit (§11) + convert issues for Alibaba Cloud (§7) |
| `build-tapp.sh` | **One-shot full chain**: base image → final gcp-tapp (Stage A app/docker/SGX/DNS + hardening + /data + Sysbox / Stage B kernel + convert + ESP / opt-in Stage C publish via `PUBLISH_AS=`) |
| `prepare-tapp.sh` | Stage B only (when a base already exists): fix A + DNS (guestfish) + nbd reset + convert + fix B |
| `publish-gcp-image.sh` | **Stage C**: publish a built qcow2 to GCP — `qemu-img` raw → oldgnu sparse `tar.gz` → `gsutil` → `gcloud compute images create` (confidential guest-os-features). Needs gcloud/gsutil auth |
| `fix-esp-grub.sh` | Sync the ESP grub only (fix B, can be run standalone against an already-converted image) |
| `test/boot-smoke-test.sh` | **Local boot smoke test**: boots a converted image under QEMU/OVMF (no real GCP CVM needed) and checks the boot chain reaches multi-user / tapp-server |
| `config_dir/` | cryptpilot convert config (`fde.toml`, `rw_overlay="ram"`) |
| `cryptpilot-fde_0.7.0_amd64.deb` | FDE **runtime installed into the target image**. **Binary, gitignored**, must be placed locally in this directory (see Prerequisites) |

> The artifact `gcp-tapp.qcow2` (~4.5G, converted / verity-sealed / hardened) is the **output** of `build-tapp.sh` and is not committed (gitignored).
> The same applies to `cryptpilot-fde_*.deb` and the tapp-server binary: the deb must be placed locally in this directory; tapp-server is pulled by default from GitHub release v0.1.0 (see below).

## Pipeline (stages)
- **Stage 0 — base prep** *(one-time, reused across builds)*: official Ubuntu 24.04 cloud image → resize to 20 GiB + gVNIC driver → base qcow2. See `cryptpilot-gcp-boot-fix.md` §0. This is the input to Stage A, not part of `build-tapp.sh`.
- **Stage A** (`build-tapp.sh`): provision app / docker / SGX / DNS, security hardening, Sysbox, and the `/data` + `br_netfilter` bakes.
- **Stage B** (`prepare-tapp.sh`, invoked by A): install the gcp kernel → fix A → `cryptpilot-convert` → sync ESP (fix B).
- *(optional)* local boot smoke test (`test/boot-smoke-test.sh`).
- **Stage C** (`publish-gcp-image.sh`): raw → sparse `tar.gz` → GCS → `gcloud compute images create`. Run standalone, or from `build-tapp.sh` via `PUBLISH_AS=<name>`.

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
OWNER_ADDRESS=0x<your-owner-address> \
KBS_URLS='"http://<kbs-host-1>:9091", "http://<kbs-host-2>:9091"' \
./build-tapp.sh <bare-ubuntu-24.04.qcow2> gcp-tapp.qcow2
```
- **Required** (no defaults — the build aborts if unset, so no deployment-specific value is ever baked in):
  - `OWNER_ADDRESS` — tapp-server owner address, written to `config.toml` `[server.permission]`.
  - `KBS_URLS` — KBS node URLs for `[kbs] node_urls`, comma-separated and quoted as shown.
- tapp-server is downloaded by default from GitHub v0.1.0 (includes the guest-components `8d71a3b4` fix, RTMR OK); if you have it locally, set `TAPP_SERVER_BIN=<path>`.
- Storage / Sysbox knobs: `DATA_ROOT` (docker data-root, default `/data/docker`), `CONTAINERD_ROOT` (default `/data/containerd`), `DOCKER_VERSION` (default `5:27.5.1-…noble`; empty = repo default), `ENABLE_SYSBOX` / `SYSBOX_VERSION` (default `0.7.0`).
- Publish (Stage C, opt-in): `PUBLISH_AS=<gcp-image-name>` publishes the built image to GCP after the build (see [Publish to GCP](#publish-to-gcp-stage-c)); `GCS_BUCKET` / `GCP_PROJECT` / `GUEST_OS_FEATURES` pass through.
- Other environment variables: `DNS_FALLBACK` `PURGE_KERNEL` `CONFIG_DIR` `FDE_PACKAGE` `ROOTFS_MODE` `IN_PLACE` `INSTALL_KERNEL` `NBD_RESET` (see the top of the script).

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
ENABLE_SYSBOX=1 OWNER_ADDRESS=0x... KBS_URLS='...' ./build-tapp.sh base.qcow2 gcp-tapp.qcow2
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
PUBLISH_AS=og-tdx-dev ENABLE_SYSBOX=1 OWNER_ADDRESS=0x... KBS_URLS='...' ./build-tapp.sh base.qcow2 og-tdx-dev.qcow2
```
Create a confidential instance from the published image with `--image=<name> --image-project=g-devops --confidential-compute-type=TDX`.

## Three core fixes (all required)
- **Fix A**: before convert, point the `/boot/vmlinuz` symlink at the gcp kernel → the cryptpilot stack goes into the correct initrd (fixes read-only / RTMR / verity).
- **Fix B**: after convert, sync the boot-partition grub.cfg + modules to the ESP (fixes the boot crash bli.mod / vmlinuz not found).
- **Application side (§8)**: tapp-server uses guest-components `8d71a3b4` (already in v0.1.0) → RTMR extend no longer misdetected.
- Also: DNS must be written to a static `/etc/resolv.conf` with **guestfish** (virt-customize wipes what it writes itself); reset nbd before convert with `modprobe nbd max_part=16`.

## Security hardening (integrated in build stage A, see doc §11)
purge: openssh-server / cloud-init / snapd / google-guest-agent / google-compute-engine (+oslogin) / google-osconfig-agent / google-cloud-ops-agent / open-vm-tools / unattended-upgrades / pollinate / landscape-common; mask the serial/local getty; switch netplan to MAC-independent DHCP.

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
