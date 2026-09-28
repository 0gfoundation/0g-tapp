# Data at rest: what the platform promises, and what it does not

An app's persistent data lives in a LUKS volume on the `/data` disk, keyed per app by the KMS
(see [README](../README.md#where-app-data-lives-encrypted-volumes)). Two of the three things
"the data is protected" is usually taken to mean are **not** provided, and an app built on the
assumption that they are will be wrong in a way nothing reports.

| | promised | mechanism |
|---|---|---|
| The host cannot **read** the data | **yes** | LUKS, key from the KMS, held only in TEE memory |
| The host cannot **forge** the data | **yes** | without the key it cannot produce chosen plaintext |
| The host cannot **corrupt** the data undetectably | **no** | [below](#corruption) |
| The data is the **latest** state | **no** | [below](#rollback) |

## Corruption

Volumes are `cryptsetup luksFormat --type luks2` with no `--integrity` (`src/boot/volume.rs`),
so the cipher is AES-XTS, which carries no authentication tag. A host that flips ciphertext bits
cannot choose what the plaintext becomes — it becomes garbage — but nothing reports that the data
was tampered with. It surfaces as a failing disk, or as an application reading nonsense.

The filesystem inside is `mkfs.ext4`, which checksums **metadata only** (`metadata_csum`):

| corrupted | detected |
|---|---|
| directories, inodes, the journal | yes, by ext4 |
| **file contents** | **no — the corrupted bytes reach the application** |

### Why it is not on by default

`--integrity` adds an HMAC per sector and closes it. Measured on an Alibaba ECS NVMe instance,
20 GB volume, `losetup --direct-io=on`, cryptpilot's `benchmarks/test.fio`:

| | seq write | rand 4K write | rand 4K read | rand write p99 |
|---|---|---|---|---|
| raw device | 173 MB/s | 7518 iops | 7479 iops | 148 ms |
| LUKS, no integrity (**today**) | 183 MB/s | 7566 iops | 7473 iops | 150 ms |
| + integrity, journal | 82 MB/s | 2243 iops | 4621 iops | **3942 ms** |
| + integrity, no journal | 163 MB/s | 3136 iops | 4691 iops | 484 ms |

**Encryption itself is free** — LUKS matches the raw device, because AES-NI makes the CPU cost
irrelevant; every cost below that line is extra I/O, not extra computation. **Integrity is not
free**: the better of the two modes loses 59% of random write throughput and 37% of random read,
and triples p99 latency. The journal mode writes everything twice and is unusable for write-heavy
work.

No-journal also trades away crash consistency: after an unclean shutdown the data and its tag can
disagree, which is reported as *tampering*. Against a host that can cut power at will, a defence
that cries wolf on every power cut is its own problem.

### Filesystems that checksum data

A filesystem that checksums file contents gets corruption detection without dm-integrity's extra
I/O, because the checksum sits in the block pointer that had to be read anyway to find the block.
On top of encryption this is sound even unkeyed: the host cannot produce plaintext matching a
checksum without the key. dstack takes this route, defaulting to ZFS, and states in its security
model that choosing ext4 instead means modified blocks reach the application.

Neither candidate is a drop-in here:

- **ZFS** suits this workload better — `recordsize` tuning helps database-shaped access and
  checksums cannot be disabled — but it is out-of-tree, so it means a kernel module inside a
  **measured** image, building against a kernel we cannot hold back (TDX runtime measurement
  needs ≥6.16; we run 6.17). The GPU driver is the precedent: 575 would not build against 6.17
  at all, and the DKMS stage dominates image build time.
- **btrfs** is in-tree and checksums data by default, but it is copy-on-write, which suits random
  overwrites of large files poorly, and the standard escape hatch `nodatacow` **also disables
  checksums** — the workloads that most want integrity are the ones you would most want it off
  for.

Both are also copy-on-write inside a loop file on another filesystem, which is not the layout
either is designed for: dstack hands ZFS a whole partition, our volumes are per-app image files.
Neither is measured yet.

## Rollback

A LUKS volume from three months ago decrypts today with the same key and passes every check we
make, because no check we make has anything to do with time. A host can keep a copy of a volume
and hand it back later; the app resumes from an old state with nothing forged and no key broken.
The data is authentic — it is simply not current, and authenticity was all that was tested.

Two forms, both available to whoever serves the block device:

- **Between runs** — present an older image at mount time.
- **During a run** — reads go to the disk on demand, so the host can return an older version of
  individual blocks at any point while the node is running. Serving reads is the host's job; TDX
  protects guest *memory*, not guest I/O.

### Why the cheap fixes do not exist

**Key rotation does not work.** Putting a counter in the key derivation and rotating the LUKS
keyslot is `O(1)` and does not reach the data: the keyslot and the data area are separate byte
ranges of a file the host owns. Keeping the current header and stapling on an old data area lets
the node unwrap the master key with the current key and decrypt old data. The master key never
changes, so it opens every snapshot of that volume.

**Rotating the master key works and costs a full re-encryption** — `O(volume size)`, tens of
minutes for a large volume, per rotation. There is no cheap version, for a structural reason:
random access requires each sector to be independently decryptable, independence means old
sectors stay readable under the same key, and making them unreadable means rewriting them.

**Hashing the volume** against a value recorded outside does close the between-runs case, and
unlike key rotation it covers the data area. It costs a full read at every mount and protects
nothing during the run, because the check happens once while every subsequent read is an
opportunity.

### What would work

Per-block authentication plus a freshness root: a Merkle tree over the volume, verified on every
read, with the root held in TEE memory — where the host cannot reach it — and recovered across
reboots from the KMS or the chain. Verification and update cost one path, `log₂(n)` ≈ 26 nodes
for a 200 GB volume, not the whole device.

No device-mapper target does this for read-write volumes:

| | in-memory root | writable |
|---|---|---|
| dm-verity | yes | **no** |
| dm-integrity | **no** — tags live on the same disk | yes |
| ext4 / btrfs / ZFS checksums | **no** — no external anchor | yes |

Building the missing half means a writable verity layer with its own crash consistency. The seam
is the hard part rather than the tree: after an unclean shutdown the volume has advanced past the
last recorded root, and the node cannot distinguish "the host rolled me back" from "I crashed
mid-write" without a write-ahead journal and a bounded roll-forward window. Wrong in either
direction and you refuse to mount healthy data, or accept rolled-back data.

Worth investigating before anyone builds that: **a checksumming filesystem already is a hash
tree.** ZFS's checksums chain up to the uberblock, and anchoring that one value externally may be
far cheaper than a new device-mapper target. This is an inference from the on-disk structure and
has not been verified.

### The field does not solve this either

dstack's security model states it directly — "neither filesystem proves that an attached disk
represents the latest application state… applications that require rollback-resistant state must
anchor a monotonic version or state commitment in an external trusted service, ledger, or
equivalent" — and cryptpilot exposes an `integrity` switch with no external anchor, which detects
corruption and not rollback. Freshness is pushed to the application layer everywhere.

Not the same problem, though the two get conflated: dstack's `instance_id` mixes in a
per-instance vTPM value so a VM **cloned** from a disk snapshot gets a different identity. That
defends identity, not data freshness, and it is a problem we do not have — our node signer is
generated randomly at every boot (`tapp-common/src/app_key/mod.rs`) and never persisted, so a
copied volume carries no identity to steal.

## What this means for an application

Whether corruption or staleness matters is the app's call; the platform's job is to be clear
about which guarantees it is not making.

**If stale data would be harmful**, anchor a monotonic version or state commitment outside the
node — the chain is the natural place, since apps are registered there already. Rollback becomes
detectable, bounded by how often you anchor. Nothing available makes it impossible.

**If corrupted contents would be harmful**, turn on integrity in the storage layer above.
Postgres has `data_checksums`; InnoDB checksums its pages. Many stores do this for
silent-corruption reasons and it covers this case too, more cheaply and more precisely than
paying for it on every block of every app.

**Neither applies to plenty of apps** — a stateless service, a cache, anything that treats
`/data` as expendable needs none of it.

## Proposed: `integrity` as a per-app data mode

Not a platform-wide default. One more value in the modes an app already declares in its compose
(`x-tapp.data`: `encrypted` | `plain` | `ram` | `scratch`), so apps that want keyed per-sector
integrity ask for it and pay for it.

The declaration is part of the compose content, which is hashed, registered on-chain and measured
— so whether an app runs with integrity protection is visible in its attestation, with no new
measured event. Same property the existing modes have.

Not implemented; tracked with its open questions in the issue tracker.
