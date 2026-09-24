# Building and running a GPU tapp image

A GPU image is the ordinary image plus one build stage. Same base, same pipeline, same
`build-tapp.sh` — `ENABLE_GPU=1` adds the NVIDIA open driver, the container toolkit and
confidential-computing mode in stage B, and nothing else changes.

It is a **separate artifact** all the same: the driver lands in the verity-sealed rootfs and the
initrd, so a GPU image measures differently from a CPU-only one and needs its own reference
values and its own AS policy id. It is not a drop-in replacement for the CPU image.

## Build

```bash
cd cvm
ENABLE_GPU=1 \
TAPP_SERVER_URL=https://github.com/0gfoundation/0g-tapp/releases/download/v0.8.0/tapp-server \
./build-tapp.sh <pristine-ubuntu-24.04.qcow2> out-gpu.qcow2
```

Add `HARDEN=0 DEV_SSH_PUBKEY="ssh-ed25519 AAAA… you@host"` for an image you need a shell on.
Do not expect to get in without it: `HARDEN=0` leaves cloud-init installed, but the image also
writes a static `/etc/resolv.conf`, which cannot resolve `metadata.google.internal`, so on GCP
cloud-init falls back to `DataSourceNone` and injects no keys. `DEV_SSH_PUBKEY` is the only way
in, on every platform.

**`build-tapp.sh` modifies its input image in place.** Copy a pristine base for every run — a
second run against a consumed base fails partway through, typically on `gpg: dearmoring failed:
File exists`.

| Variable | Default | Notes |
|---|---|---|
| `ENABLE_GPU` | `0` | `1` adds stage `[1a/4]` |
| `NVIDIA_DRIVER_BRANCH` | `580` | open kernel module; see below |
| `BOOT_FORMAT` | `grub` | `uki` does not currently fit the 105 MB ESP on a GPU image |

The GPU stage takes roughly 60–90 minutes, most of it DKMS compiling the driver.

### Why driver 580, and why the open module

Confidential computing **requires** the open kernel module — `-open` is not a preference.

580 is the floor GCP's confidential-GPU guidance gives ("580 or higher"), and here the floor is
real rather than advisory: 575.57.08 does not build against this image's 6.17 kernel, failing on
`implicit declaration of function 'dma_buf_attachment_is_dynamic'`, a symbol 6.17 removed from
the public dma-buf headers and that NVIDIA's conftest does not probe for. Alibaba pins 550/570
because their platform runs a 5.10 kernel; ours must be ≥6.16 for the TDX RTMR interface, so a
newer driver is the matched pair and there is nothing to retreat to.

Fabric Manager (needed for NVSwitch on multi-GPU hosts, and for Protected PCIe with it) comes
from the **unversioned** package: NVIDIA drops the branch suffix on its newest line, so
`nvidia-fabricmanager-575` exists but 580's counterpart is plain `nvidia-fabricmanager`. The
build pins it to the version the driver itself resolved to, because that package now resolves to
610/615 and Fabric Manager has to match the driver exactly. It is installed but left **disabled**:
only multi-GPU hosts need it, and enabling a service at runtime does not change the measurement
whereas installing it later would.

## Running

GCP: `a3-highgpu-1g` (1× H100 80GB) or larger, with TDX.

```bash
gcloud compute instances create <name> \
  --machine-type=a3-highgpu-1g \
  --image=<your-gpu-image> --image-project=<project> \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --provisioning-model=SPOT \
  --boot-disk-size=100GB \
  --create-disk=name=<name>-data,size=200GB,auto-delete=yes
```

### A GPU host needs its data disk named, not just attached

**Attaching a blank disk is not enough on a GPU machine type.** The image auto-provisions `/data`
by looking for exactly one blank non-boot disk, and GPU machine types break that: GCP attaches
local SSDs to every A2/A3 unconditionally and they cannot be declined, so `a3-highgpu-1g` always
has two extra blank disks. The build excludes GCP scratch disks by their NVMe model string
(`nvme_card<N>` for local SSD vs `nvme_card-pd` for a persistent disk), which covers GCP — but
the underlying rule still cannot work on any host with more than one genuine spare disk, bare
metal included.

The node still boots and is reachable; it refuses to run apps (`FAILED_PRECONDITION` on
StartApp) and says why on the console. Give it the disk over the API — the `ProvisionDataDisk`
RPC, owner only, so claim the node first:

```bash
tapp-cli -s <node> provision-data-disk --dry-run -k <key>              # what does it see?
tapp-cli -s <node> provision-data-disk --device /dev/nvme0n2 -k <key>
systemctl restart tapp-server                                          # restores file logging
```

The dry run prints every disk the node considered, with the ephemeral ones marked — on
`a3-highgpu-1g` that is two local SSDs and your data disk, which is exactly the picture that
explains the refusal. Naming an ephemeral disk is allowed but is a deliberate choice: its
contents vanish on stop/start.

An existing ext4 disk is adopted (relabelled, data preserved), never reformatted; any other
filesystem is refused outright. Once labelled `tapp-data` the disk is found by label on every
later boot, so this is one time per disk and survives reboots and migration.

Both outcomes are written into the runtime measurement as a `provision_data_disk` event carrying
`action` (`formatted` or `adopted`), the device and the filesystem UUID. Know what you are doing
when you adopt: the node inherits content it did not create, and while app volumes are LUKS-sealed
against forgery they can still be *stale*, and `/data/log/tapp/` is protected by nothing at all.
The event is what lets a verifier tell the two cases apart later — see
`docs/EVIDENCE_AND_AS_VERIFICATION.md`.

If you would rather the node never see an unprovisioned disk, prepare it anywhere first — the
label is the whole contract:

```bash
mkfs.ext4 -L tapp-data <device>
```

On a cloud that means attaching the disk to any ordinary VM once. To skip that per node, turn
one labelled disk into an image and create every node's data disk from it:

```bash
gcloud compute images create tapp-data-blank --source-disk=<labelled-disk> --source-disk-zone=<zone>
gcloud compute disks create <node>-data --image=tapp-data-blank --size=200GB --zone=<zone>
```

## Checking a running GPU node

Four things, in order — each is meaningless without the one before it:

```bash
# 1. the driver built for the kernel this image boots, and the GPU is visible
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv

# 2. confidential computing is actually ON (not merely supported)
nvidia-smi conf-compute -f          # -> CC status: ON
nvidia-smi conf-compute -grs        # -> Confidential Compute GPUs Ready state: ready

# 3. the GPU half of the attestation is present
tapp-cli get-evidence --server http://<node>:50051 --nonce $(openssl rand -hex 32)
#    decode the evidence and check gpu_evidence is not null, cc_enabled is true

# 4. the GPU report is bound to THIS quote, not replayed
#    see docs/EVIDENCE_AND_AS_VERIFICATION.md § GPU evidence
```

CC mode is turned on by a drop-in on `nvidia-persistenced` (`nvidia-smi conf-compute -srs 1`),
which runs once the driver is up on the real machine; persistence mode is required anyway,
because the CPU↔GPU SPDM session needs it. `ecdsa_generic` and `ecdh` are loaded at boot via
`/etc/modules-load.d/nvidia-cc-lkca.conf` — the Linux kernel crypto API that session depends on.

## Verified

GCP `a3-highgpu-1g`, TDX confidential VM, image built from Ubuntu 24.04 with kernel
6.17.0-42-generic, driver 580.178.04, tapp-server 0.8.0:

| | |
|---|---|
| driver + GPU visible | `NVIDIA H100 80GB HBM3, 580.178.04, 81559 MiB` |
| confidential mode | `CC status: ON`, `Ready state: ready` |
| `gpu_evidence` | present, `cc_enabled: true`, VBIOS `96.00.D9.00.01`, report + certificate chain |
| GPU↔CPU binding | GPU report offset 4 == quote `report_data[0:32]` == `sha512(runtime_data)[0:32]` |

## Building through CI

`build-cvm` takes `enable_gpu`. It appends `-gpu` to the image version, which is what keys the
image name, the reference-value path and the AS policy id — so a GPU image can never land on a
CPU image's reference values:

| | CPU | GPU |
|---|---|---|
| image name | `og-tdx-dev-grub-v0-9-0` | `og-tdx-dev-grub-v0-9-0-gpu` |
| reference values | `grub/v0.9.0/dev.json` | `grub/v0.9.0-gpu/dev.json` |
| AS policy id | `0g-tapp-grub-v0.9.0-dev` | `0g-tapp-grub-v0.9.0-gpu-dev` |

Verifiers must be told the GPU policy id; it is a different identity, deliberately.

## Not yet done

- **UKI.** The 105 MB ESP on the GCP image layout cannot hold a GPU UKI, and the partition is
  sandwiched between others so it cannot grow in place. GPU images use grub until the ESP is
  enlarged in stage 0.
- **Multi-GPU.** Fabric Manager is installed and version-matched but has only been reasoned
  about, not run: every measurement above is from a single-GPU host.
- **The GPU report's signature** is not checked by anything in this repo yet. The binding check
  in `docs/EVIDENCE_AND_AS_VERIFICATION.md` proves the report is fresh and about this node;
  proving it is genuine means verifying it against NVIDIA's device identity (NRAS or a local
  verifier), which no policy here does.
