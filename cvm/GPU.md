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

### The data disk on a GPU host

GPU machine types attach ephemeral local SSDs unconditionally — `a3-highgpu-1g` gets two, and
they cannot be declined — so a naive "find the one blank disk" rule never resolves there. The
image excludes cloud scratch by its NVMe model string (`nvme_card<N>` for local SSD vs
`nvme_card-pd` for a persistent disk), which means **attaching one data disk is enough and it
provisions itself**, exactly as on a CPU instance.

The local SSDs are left unused. They are wiped on stop/start, so they cannot hold `/data`.

If a host has more than one genuine spare disk, the node refuses to guess rather than risk
formatting the wrong one, and says so on the console — naming the disks it found and the command
below, so the serial log shows why the node is idle. Label the intended disk beforehand, on any
machine with a shell:

```bash
mkfs.ext4 -L tapp-data <device>
```

A disk carrying that label is used directly on every boot with no guessing; one already holding
ext4 is adopted by relabelling, never reformatted. To skip the per-node step on a cloud, turn one
labelled disk into an image and create every node's data disk from it:

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
