# Data at rest: what the platform promises, and what it does not

An app's persistent data lives in a LUKS volume on the `/data` disk, keyed per app by the KMS
(see [README](../README.md#where-app-data-lives-encrypted-volumes)). It is easy to read that as
"the data is protected" and stop there. It is worth being precise, because two of the three
things people usually mean by that are **not** provided, and an app built on the assumption that
they are will be wrong in a way nothing reports.

| | promised | mechanism |
|---|---|---|
| The host cannot **read** the data | **yes** | LUKS, key from the KMS, held only in TEE memory |
| The host cannot **forge** the data | **yes** | without the key it cannot produce chosen plaintext |
| The host cannot **corrupt** the data undetectably | **no** | see [Corruption](#corruption-tampering-that-is-not-detected) |
| The data is the **latest** state | **no** | see [Rollback](#rollback-old-data-is-valid-data) |

The first two are what encryption gives. The last two are what encryption cannot give, and no
amount of it will.

## Corruption: tampering that is not detected

The volumes are `cryptsetup luksFormat --type luks2` with no `--integrity` (`src/boot/volume.rs`),
so the cipher is AES-XTS, which carries no authentication tag. A host that flips ciphertext bits
cannot choose what the plaintext becomes — it becomes garbage — but **nothing reports that the
data was tampered with.** It surfaces as a failing disk, or as an application reading nonsense.

The filesystem inside the volume is `mkfs.ext4`, which checksums **metadata only**
(`metadata_csum`). So:

| what was corrupted | detected |
|---|---|
| directories, inodes, the journal | yes, by ext4 |
| **file contents** | **no — the corrupted bytes reach the application** |

### Why this is not fixed by default

`--integrity` adds an HMAC per sector, which does close it. Measured on an Alibaba ECS NVMe
instance, 20 GB volume, `losetup --direct-io=on`, using cryptpilot's `benchmarks/test.fio`:

| | seq write | rand 4K write | rand 4K read | rand write p99 |
|---|---|---|---|---|
| raw device | 173 MB/s | 7518 iops | 7479 iops | 148 ms |
| LUKS, no integrity (**today**) | 183 MB/s | 7566 iops | 7473 iops | 150 ms |
| + integrity, journal | 82 MB/s | 2243 iops | 4621 iops | **3942 ms** |
| + integrity, no journal | 163 MB/s | 3136 iops | 4691 iops | 484 ms |

Two things worth reading off that table. **Encryption itself is free** — LUKS matches the raw
device, because AES-NI makes the CPU cost irrelevant; every cost below it is extra I/O, not
extra computation. And **integrity is not free**: the better of the two modes still loses 59% of
random write throughput and 37% of random read, and triples p99 latency. The journal mode,
which writes everything twice, is unusable for anything write-heavy.

The no-journal mode also trades away crash consistency: after an unclean shutdown the data and
its tag can disagree, which is reported as **tampering**. Against a host that can cut power at
will, a defence that cries wolf on every power cut is its own problem.

### Filesystems that checksum data, and why they are not a free win either

A filesystem that checksums file contents gets corruption detection without dm-integrity's
extra I/O, because the checksum is stored in the block pointer that had to be read anyway to
find the block. On top of encryption this is sound even though the checksum is unkeyed: the host
cannot produce plaintext matching a checksum without the key, so tampering still shows up as a
checksum failure. dstack takes this route, defaulting to ZFS, and says plainly in its security
model that choosing ext4 instead means modified blocks reach the application.

Neither candidate is a drop-in for us:

- **ZFS** suits this workload better — `recordsize` tuning genuinely helps database-shaped
  access, and checksums cannot be turned off. But it is out-of-tree, so it means shipping a
  kernel module inside a **measured** image and keeping it building against a kernel we cannot
  hold back (TDX runtime measurement needs ≥6.16; we run 6.17). We already maintain one such
  dependency for the GPU driver and know what it costs: driver 575 would not build against 6.17
  at all, and the DKMS stage dominates image build time.
- **btrfs** is in-tree, so none of that applies, and it checksums data by default. But it is
  copy-on-write, which is poorly suited to random overwrites of large files, and the standard
  escape hatch — `nodatacow` — **also disables checksums**. The workloads that most want
  integrity are the ones you would most want to turn it off for.

Both are also copy-on-write inside a loop file on another filesystem, which is not the layout
either is designed for; dstack hands ZFS a whole partition, while our volumes are per-app image
files. None of this is measured yet, and it should be before anything is chosen.

## Rollback: old data is valid data

A LUKS volume from three months ago decrypts today with the same key and passes every check we
make, because no check we make has anything to do with time. A host can keep a copy of a
volume and hand it back later; the app resumes from an old state with nothing forged and no key
broken. The data is authentic — it is simply not current, and authenticity was all we tested.

Two forms, both available to whoever serves the block device:

- **Between runs**: present an older image at mount time.
- **During a run**: reads go to the disk on demand, so the host can return an older version of
  individual blocks at any point while the node is running. This is not an exotic capability;
  serving reads is the host's job, and TDX protects guest *memory*, not guest I/O.

### Why the obvious fixes do not work

**Rotate the key per epoch.** Put a counter in the KMS's key derivation so old snapshots cannot
be opened, and rotate the LUKS keyslot — `O(1)`, no re-encryption. This was our proposal and it
is **broken**: the keyslot and the data area are separate byte ranges of a file the host owns.
Keep the current header, staple on an old data area, and the node unwraps the master key with
the current epoch key and decrypts the old data. `dd` defeats it. The master key never changes,
so it opens every snapshot of that volume, past and future.

A per-app counter is also wrong on its own terms: nodes re-key their own disks independently
while sharing one counter, so the first node to rotate locks every other node out permanently —
and a locked-out node cannot rotate, because rotating requires opening the volume first.

**Rotate the master key instead.** This does work, and costs a full re-encryption —
`O(volume size)`, tens of minutes for a large volume, every rotation. The reason there is no
cheap version is structural: random access requires each sector to be independently decryptable,
independence means old sectors stay readable under the same key, and making them unreadable
means rewriting them.

**Hash the volume and compare.** A hash over the whole volume, recorded somewhere the host
cannot roll back, does close the between-runs case — and unlike the epoch scheme it covers the
data area, so `dd` does not defeat it. It costs a full read at every mount, and it protects
nothing during the run, because the check happens once while every subsequent read is an
opportunity.

### What would actually work, and why we are not building it

Per-block authentication plus a freshness root: a Merkle tree over the volume, verified on every
read, with the root held in TEE memory — where the host cannot reach it — and recovered across
reboots from the KMS or the chain. Verification and update cost one path, `log₂(n)` ≈ 26 nodes
for a 200 GB volume, not the whole device.

There is no such device-mapper target for read-write volumes:

| | in-memory root | writable |
|---|---|---|
| dm-verity | yes | **no** |
| dm-integrity | **no** — tags live on the same disk | yes |
| ext4/btrfs/ZFS checksums | **no** — no external anchor | yes |

Each has one half. Building the other half means a writable verity layer with its own crash
consistency, which is research-grade work. The seam is the hard part rather than the tree: after
an unclean shutdown the volume has advanced past the last recorded root, and the node cannot
distinguish "the host rolled me back" from "I crashed mid-write" without a write-ahead journal
and a bounded roll-forward window. Get that wrong in either direction and you either refuse to
mount healthy data or accept rolled-back data.

One observation worth keeping if this is ever revisited: **a checksumming filesystem already is
a hash tree**. ZFS's checksums chain up to the uberblock; anchoring that one value externally
may be far cheaper than building a device-mapper target. This has not been verified and is an
inference from the on-disk structure, not a design.

### Nobody else solves this either

This is not a gap specific to us. dstack's security model states it directly — "neither
filesystem proves that an attached disk represents the latest application state… applications
that require rollback-resistant state must anchor a monotonic version or state commitment in an
external trusted service, ledger, or equivalent" — and cryptpilot exposes an `integrity` switch
with no external anchor, which detects corruption and not rollback. The whole field pushes
freshness to the application layer.

Worth separating from rollback, because they are often conflated: dstack's `instance_id` mixes
in a per-instance vTPM value so a VM **cloned** from a disk snapshot gets a different identity.
That defends identity, not data freshness, and we do not have the problem it solves — our node
signer is generated randomly at every boot (`tapp-common/src/app_key/mod.rs`) and is never
persisted to disk, so a copied volume carries no identity to steal.

## What this means for an application

Whether corruption and staleness matter is the app's call, and the platform's job is to be clear
about which guarantees it is not making.

**If stale data would be harmful**, anchor a monotonic version or a state commitment outside the
node — the chain is the natural place, since apps are registered there already. Rollback then
becomes detectable, bounded by how often you anchor. Nothing available makes it impossible.

**If corrupted contents would be harmful**, turn on whatever integrity the storage layer above
already offers. Postgres has `data_checksums`; InnoDB checksums its pages; many stores do this
for silent-corruption reasons and it covers this case too. That is cheaper and better targeted
than paying for it on every block of every app.

**Neither applies to plenty of apps.** A stateless service, a cache, anything that treats
`/data` as expendable, needs none of this.

## Proposed: `integrity` as a per-app data mode

Rather than a platform-wide default that makes every app pay, add it to the modes an app already
declares in its compose (`x-tapp.data`: `encrypted` | `plain` | `ram` | `scratch`). An app that
wants keyed per-sector integrity asks for it and pays for it.

The declaration is part of the compose content, which is hashed, registered on-chain and
measured — so **whether an app runs with integrity protection is visible in its attestation**,
with no new measured event needed. That is the same property that already makes the existing
data modes verifiable.

Not implemented. Open questions: which dm-integrity mode to expose given that no-journal
misreports crashes as tampering, and whether existing volumes can be migrated or must be
recreated (the tag area changes the layout, so in-place conversion is not available).
