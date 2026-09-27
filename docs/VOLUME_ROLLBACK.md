# Rollback protection for encrypted volumes (design)

**Status: design, not built.** Nothing in this document is implemented. It exists to be argued
with before code is written.

Encryption already gives an app's data two properties: the host cannot read it, and it cannot
write anything meaningful into it. What it gives no property against is **age**. A LUKS volume
from three months ago decrypts today with exactly the same KMS-derived key and passes every
check we make — because we make no check that has anything to do with time.

So an untrusted host has a move we currently cannot see, let alone stop: keep a copy of an
app's volume, hand it back later, and the app resumes from an old state. No ciphertext was
forged and no key was broken. The data is authentic. It is just not *current*, and authenticity
was the only thing we were ever testing for.

This document proposes making stale volumes **impossible to open** rather than detectable, and
is honest about the part of the problem that approach does not reach.

## What the threat actually is

Three distinct attacks get lumped together as "rollback". They need different answers, and
conflating them is how a design ends up covering one and quietly missing two.

| | attack | current defence |
|---|---|---|
| **A** | swap the whole volume for an older snapshot, between runs | none |
| **B** | replay individual blocks of the volume while the node is running | none |
| **C** | corrupt blocks so they decrypt to garbage | none |

**C is worth stating plainly, because it is commonly assumed to be covered and is not.** Our
volumes are `cryptsetup luksFormat --type luks2` with no `--integrity` (`src/boot/volume.rs`),
so the cipher is XTS, which has no authentication tag. A host that flips ciphertext bits
produces garbage plaintext, not chosen plaintext — but nothing anywhere reports that the data
was tampered with. It looks like a failing disk.

The contrast with the root filesystem is the whole lesson. The rootfs is dm-verity: a hash tree
whose root is in the boot measurement. Tampering fails the hash, and an old rootfs fails the
measurement. It is protected not because it is encrypted — it is not — but because **its
content is anchored to something the host cannot roll back.** The data volume is encrypted and
anchored to nothing.

## Proposal: make the key a function of the epoch

Today the volume key depends only on the app:

```
key = KMS.derive(app_id, material="fde")
```

Give the KMS a monotonically increasing **epoch** per volume, and put it in the derivation:

```
key = KMS.derive(app_id, material="fde", epoch=N)
```

The KMS serves only the current epoch's key. An older snapshot's LUKS header holds a keyslot
for an older epoch, whose key nobody will ever hand out again. The old volume does not fail a
check — **there is no check.** It simply cannot be opened.

That distinction is the point of the design. Every scheme that detects staleness depends on
somebody reading the evidence and acting on it, and on every code path remembering to look.
A key that does not exist needs no vigilance.

### It costs one keyslot rotation, not a re-encryption

LUKS2 keyslots make advancing an epoch cheap: add a slot for the new key, remove the old one.
The bulk data is never rewritten, so rotation is O(1) in the size of the volume — milliseconds
on a volume of any size.

```
cryptsetup luksAddKey    <img>   # install epoch N+1
cryptsetup luksRemoveKey <img>   # retire epoch N
```

### Why the KMS rather than a TPM

A TPM NV monotonic counter is the textbook answer and the wrong one here:

- Bare-metal TDX does not reliably expose a vTPM to the guest, and bare metal is where this
  is going (`cvm/BARE_METAL.md`).
- On GCP the vTPM is the platform's, so trusting it means trusting the platform — which is
  the assumption TDX exists to remove.

The KMS is already on the critical path: no key, no volume. Giving it one more field to
remember adds no new trusted party and no new failure mode, which is worth more than the
theoretical purity of a hardware counter.

## The rotation protocol

The obvious ordering — advance the epoch, then re-key the disk — locks the node out of its own
data if it dies in between. The order below cannot, because **the KMS keeps serving the old key
until the node confirms the new one is installed.**

```
1. node, attested, requests the volume key      -> KMS returns key(N)
2. node opens the volume with key(N)
3. node requests an advance                     -> KMS mints key(N+1), marks N+1 PENDING
                                                   and keeps serving BOTH N and N+1
4. node: luksAddKey    with key(N+1)               (either key opens the volume)
5. node: luksRemoveKey with key(N)                 (only N+1 opens it)
6. node confirms                                -> KMS COMMITS: current = N+1, stops serving N
```

Every crash point leaves the volume openable:

| crash after | on disk | KMS serves | recovery |
|---|---|---|---|
| 3 | N | N, N+1 | open with N, retry from 3 |
| 4 | N, N+1 | N, N+1 | either key, retry from 5 |
| 5 | N+1 | N, N+1 | open with N+1, retry from 6 |

**Step 6 must be last.** Inverting it — KMS commits before the node has installed the new
keyslot — turns any crash in the window into unopenable data.

### The PENDING state is the part that will break

While an advance is pending, both keys are served, so a snapshot at epoch N is still openable.
That window is meant to be seconds. If a crash leaves a PENDING record and nothing ever clears
it, the window becomes permanent and **the protection is silently gone** — the system looks
healthy and defends nothing.

This is the same failure shape as the reference-value guard that checked a path nothing wrote
(fixed in #127): a control that is present, believed, and inert. Whatever is built here needs
PENDING to expire on a timeout and to converge on the next open, and needs a test that fails
when it does not.

### Fencing comes free

Two nodes cannot hold the same volume: whichever completes a rotation has removed the other's
keyslot. Migration gets mutual exclusion without a separate lease mechanism. This is a
consequence worth keeping deliberately rather than discovering by accident.

## When to advance

**On every open.** The volume is opened once per app per boot: `start_app` opens the LUKS
mapping, `stop_app` unmounts but deliberately leaves the mapping open (`src/boot/mod.rs`, and
the next `start_app` short-circuits on `mountpoint -q`). So "per open" means "per app per
boot", which is the right granularity and needs no new trigger — the call site already exists
in `ensure_luks`.

**And periodically while running.** Advancing only on open leaves a gap nobody notices: an app
that has not been started since its last run sits at an unchanged epoch, so any snapshot taken
during that run stays openable for as long as the app is idle. Advancing on close would seem to
fix it, but close cannot be relied on — a crash never gets there, and a defence that depends on
a graceful shutdown defends nothing against a host that can pull the power.

An hourly advance bounds the exposure to the interval instead of to the idle time, at one KMS
round trip and one keyslot rotation per hour.

## What this does not solve

**Attack A only.** Within one epoch, B and C stand untouched: the same key opens both the real
block and a replayed old one, and XTS still reports nothing when a block is corrupted.

The answer to B and C is authenticated integrity — dm-integrity, or a Merkle tree over the
volume — with the root held in TEE memory while the node runs, where the host cannot reach it.
A replayed or corrupted block then fails against a root the host cannot influence.

That splits the problem cleanly:

| | protects | mechanism |
|---|---|---|
| while running | blocks (B, C) | Merkle root in TEE memory |
| across reboots | the whole volume (A) | epoch key |

The genuinely hard part is the seam. When the machine reboots, TEE memory is gone, and the
node must recover "what was my root last time" from somewhere the host cannot roll back. That
is the same question the epoch answers, which suggests the KMS should hold the root alongside
the epoch and hand both back at open.

At that point a comparison reappears — the node checks the volume's root against the KMS's.
That is acceptable where the earlier check was not: the reference comes from an attested remote
party, not from the same disk being tested. Checking a disk against a number stored on that
disk is circular; checking it against the KMS is not.

**Crash recovery is where this gets hard, and it should be designed before anything is
written.** After an unclean shutdown the volume may have advanced past the root the KMS holds.
The node cannot distinguish "the host rolled me back" from "I crashed mid-write" without a
write-ahead journal and a bounded roll-forward window. Underestimating this is how such systems
end up either refusing to mount healthy data or accepting rolled-back data — and it is a
separate piece of work from the epoch scheme, which is why the epoch scheme is proposed on its
own first.

## Scope

Only `encrypted` volumes need this. The other modes already answer the question or do not ask
it:

| mode | epoch needed | why |
|---|---|---|
| `encrypted` | **yes** | the whole subject of this document |
| `scratch` | no | the key is re-derived per boot, so old volumes are already unopenable |
| `plain` | no | not encrypted; whoever holds the disk reads it, by declaration |
| `ram` | no | never on disk |

`scratch` is worth looking at, because it already has what we are trying to build — a key that
changes often enough that stale copies are dead — and pays for it by discarding the data. The
epoch proposal is `scratch`'s rotation schedule applied to a volume that keeps its contents,
which keyslot rotation makes affordable.

## Work items

1. **Epoch in the KMS**: per-`(app_id, fde)` counter, two-phase advance, PENDING expiry.
   Consumer side: thread the epoch through `kms_client` and `volume::ensure_luks`.
2. **Periodic advance** while a volume is open.
3. **dm-integrity** on the volume, and the measured/KMS-held root that makes it mean something.
   Independent of 1 and 2; heavier, with a real write-amplification cost to measure first.
4. **Crash recovery** for 3. Design before code.

1 and 2 are worth doing on their own: they close attack A completely, and A is the one that
needs no privileged position on the host — only a copy of a file.
