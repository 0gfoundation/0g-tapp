# Running tapp on a bare-metal TDX host

Everywhere else, the cloud creates the Trust Domain for you: you import an image, tick a
confidential-computing box, and something else runs QEMU. On bare metal **you are the hypervisor
operator** — you launch the TD yourself. Nothing about the image changes; what changes is that the
three things the cloud was quietly doing become yours: enabling TDX on the host, making quote
generation work, and starting the TD.

Verified end to end on an Alibaba Cloud `ecs.ebmg8i.48xlarge` (Emerald Rapids, 2 sockets, 1 TB RAM)
in `cn-beijing`, with a `uki` / `HARDEN=1` image. Where a step is **not** yet verified this document
says so.

**Two flavours of "bare metal", and they differ in exactly one place.** On a cloud bare-metal
*instance* you get the machine without a hypervisor in the way, but the provider still selected it,
set its BIOS and registered it with Intel. On hardware you bought, those three are yours. Steps 0
and 2-5 are identical either way; only step 1 forks, and [§1b](#1b-and-if-the-hardware-is-genuinely-yours)
covers the owned case.

---

## 0. What the host must already have

| | Check | Expected |
|---|---|---|
| CPU + BIOS | `sudo dmesg \| grep -i tdx` | `virt/tdx: BIOS enabled: private KeyID range [1, N)` and `module initialized` |
| KVM | `cat /sys/module/kvm_intel/parameters/tdx` | `Y` |
| QEMU | `qemu-system-x86_64 --version` | a TDX build, e.g. `8.2.2 (… +tdx1.1)` |
| SGX devices | `ls /dev/sgx_*` | `sgx_enclave`, `sgx_provision` — quote generation runs in an SGX enclave |
| QGS | `systemctl is-active qgsd` | `active`, listening on **vsock port 4050** (`ss -lnp \| grep 4050`) |

The host side of all of this is [`canonical/tdx`](https://github.com/canonical/tdx)'s
`setup-tdx-host.sh`, and it is **platform-neutral** — the same script is right on a cloud instance
and on hardware you bought. Its *attestation* half is not; see the next section.

## 1. Quote generation — the one genuinely non-obvious step

A TD can boot without this, produce evidence, and look fine. But the quote's certificate chain has
to root at Intel, and the PCK certificate for *this specific CPU package set* comes from a **PCCS**.
No PCCS that can serve this platform ⇒ no verifiable quote ⇒ tapp's whole point is gone.

Who can serve it depends on **who owns the hardware**, because the owner is who registers it with
Intel:

| | PCCS to use | Intel subscription key | Platform registration |
|---|---|---|---|
| **Cloud instance** (incl. bare-metal instances) | the provider's | not needed | already done by them |
| **Hardware you bought** | your own | you must subscribe | you must register (multi-socket ⇒ multi-package) |

`canonical/tdx`'s `setup-attestation-host.sh` walks the *second* row: install a local PCCS,
`pccs-configure`, paste an Intel PCS subscription key. On a cloud instance that is the wrong row,
and following it leaves you with a local PCCS that serves nothing — which is exactly how the host
this was verified on had been set up: local PCCS running, `ApiKey` empty (the prompt says "Press
ENTER to skip"), `mpa_manage` reporting `registration status NOK: platform not registered`.

**On Alibaba Cloud**, point the QCNL at their DCAP instead. Region comes from IMDS:

```bash
T=$(curl -s -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 60" http://100.100.100.200/latest/api/token)
REGION=$(curl -s -H "X-aliyun-ecs-metadata-token: $T" http://100.100.100.200/latest/meta-data/region-id)

sudo cp /etc/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf.bak
# "pccs_url": "https://sgx-dcap-server-vpc.${REGION}.aliyuncs.com/sgx/certification/v4/"
# "use_secure_cert": true
sudo rm -rf /root/.dcap-qcnl /tmp/.dcap-qcnl ~/.dcap-qcnl   # drop cached (empty) PCK collateral
sudo systemctl restart qgsd
sudo systemctl disable --now pccs                            # the local one serves nothing; stop it
```

Other providers follow the same shape with their own endpoint (Azure has THIM, GCP registers its
own fleet). **The rule is: whoever owns the hardware registers it, and you point at their service.**

### 1b. …and if the hardware is genuinely yours

**Not verified** — everything above was done on a cloud bare-metal *instance*, where the provider
had already handled selection, BIOS and registration. On hardware you buy, those three become
yours. They are the whole difference, and only the third is hard.

**Procurement — the one irreversible decision.** TDX is a property of the CPU *SKU*, not of the
generation: plenty of Sapphire Rapids and later Xeons do not have it. Check the exact model number
on [Intel ARK](https://ark.intel.com) for "Intel® Trust Domain Extensions (Intel® TDX)" before
buying; Core and Xeon W lines do not have it at all. Get the CPU wrong and nothing else helps.

**Single socket is simpler.** Dual socket is fine — the verified host has two — but registration
then has to cover both packages (see below), which is one more thing to get right.

TDX support is a *firmware* feature as much as a silicon one, and the board's BIOS has to expose
it. Major OEMs did not ship it at launch, so an older BIOS may simply have no such menu — that is
**usually a BIOS update away, not a dead end**. Confirm with the vendor which firmware version
first has it.

**BIOS settings.** Menu paths and names vary by vendor, so get the vendor's own documentation;
Intel's reference list is roughly: enable **TME**, **TME-MT**, **TDX**, **SEAM Loader** and
**SGX**, set **TME-MT/TDX key split** to a non-zero value, and optionally enable **Total Memory
Encryption Bypass**. Four are worth understanding rather than just ticking:

- **`Total Memory Encryption Bypass = Enable`** reads like a downgrade and is not: it lets the
  *host* and ordinary VMs skip the encryption engine for performance. TD memory is encrypted
  regardless.
- **`TME-MT memory integrity = Disable`** also reads like one, and is also correct — TDX uses its
  own integrity mechanism, not MKTME's older one.
- **`SGX = Enable`** is the one people omit, because they wanted TDX, not SGX. But **quote
  generation runs in an SGX enclave** (hence `/dev/sgx_*` and QGS in §0). No SGX ⇒ the TD produces
  a TDREPORT that never becomes a quote ⇒ every attestation-dependent thing here is dead.
- **`SEAM Loader = Enable`** is what lets the TDX module be loaded from the ESP or BIOS — which is
  how the module gets *updated* later. Disable it and you are frozen on whatever the BIOS shipped,
  so `tcb_status` goes `OutOfDate` eventually and stays there.

The `key split` value bounds how many TDs can run at once; it is a BIOS setting, so raising it
later costs a reboot. Verify from the OS afterwards rather than trusting the save — §0's checks are
exactly that, plus `canonical/tdx`'s own verification script.

**Attestation is the part that actually costs time.** Here you *do* follow
`canonical/tdx`'s `setup-attestation-host.sh`, which the cloud case should skip:

1. Subscribe to the [Intel PCS](https://api.portal.trustedservices.intel.com/provisioning-certification)
   to get a provisioning-certification subscription key (two are issued, for rotation).
2. `sudo /usr/bin/pccs-configure` and paste it at `Set your Intel PCS API key`. **This is the prompt
   that says "(Press ENTER to skip)"** — skipping it is how the verified host ended up with a PCCS
   that served nothing.
3. Register the platform with Intel. On a multi-socket box this is **multi-package registration**
   via the MPA (`mpa_manage`, `mpa_registration_tool`), which needs outbound access to Intel's
   registration service. Confirm with `sudo /opt/tdx/attestation/check-registration.sh` — anything
   other than a registered status means quotes will not verify.

Budget roughly: hardware selection and BIOS a day, the host stack an hour (it is a script), and the
Intel subscription plus registration the rest of a week, mostly waiting on the subscription. That
week is precisely what a cloud bare-metal instance saves you, and it is why the verified path above
is worth preferring while the architecture is what you are testing.

**What owning it also changes.** The TDX module comes from the BIOS, so on a cloud instance its
currency is the provider's to deliver (see the `tcb_status` note below) — on your own hardware
**you can finally fix it**, and equally, nobody else will. Keeping `tcb_status` current becomes
entirely yours: microcode, TDX module and SGX packages, driven by Intel's TCB recovery
announcements. So does the BMC: whoever holds it can change the BIOS, including turning TDX off.

Confirm it worked from the quote, not from the config — `verify-app` reaching a `tcb_status` at all
means the AS retrieved this platform's collateral:

```
AS : ear.status=… tcb_status=UpToDate advisories=0      # collateral retrieved, TCB current
AS : ear.status=… tcb_status=OutOfDate advisories=5     # collateral retrieved, firmware behind
```

> **`tcb_status` must be `UpToDate`** for `verifier/policy.rego` to accept the quote. It is a verdict
> on a *set* of versions — CPU microcode, TDX module (SEAM), SGX PSW — so being behind on any one of
> them fails it. Two of those you control (`intel-microcode`, packages); the **TDX module comes from
> the BIOS**, so on a cloud instance its currency is the provider's to deliver. Worth settling with
> them before depending on such a host: *who updates it, and how quickly after Intel publishes?*
> On the verified host neither had ever been updated — microcode was absent entirely
> (`intel-microcode: Installed: (none)`) and the TDX module was 19 months old — giving
> `OutOfDate`/5 advisories. See [`docs/TDX_BOOT_CHAIN_VERIFICATION.md`](../docs/TDX_BOOT_CHAIN_VERIFICATION.md).

## 2. The image — unchanged, but build it right

Bare metal takes the **same image** as every cloud; see [`README.md`](README.md). Two choices matter:

- **`BOOT_FORMAT=uki`** — match production rather than the `grub` default.
- **`DEV_SSH_PUBKEY=…`** if you want to log in. Bare metal has **no metadata service** — a
  self-launched TD is handed nothing — so the cloud-injection route the `HARDEN=0` dev variants
  relied on does not exist here. A baked key is the only way in besides the serial console. See
  [Dev SSH access](README.md#dev-ssh-access-cloud-independent).

The build still needs an **Alinux/al8 host** (`cryptpilot-convert` is packaged only for it), so
build on the al8 CI runner and copy the qcow2 over. It is ~4 GB; between two cloud regions expect a
few minutes, through a laptop expect an hour.

## 3. Launch the TD

```bash
qemu-img create -f qcow2 tapp-data.qcow2 200G     # the /data disk — exactly one, see below
sudo ./run-tapp-td.sh                             # see the invocation below
```

The TDX-specific flags are `canonical/tdx`'s own (`/opt/tdx/guest-tools/run_td`,
`direct-boot/boot_direct.sh` on a host set up by it) — take them from there rather than from a blog,
because they have changed across QEMU versions:

```bash
qemu-system-x86_64 \
  -accel kvm -cpu host \
  -m 64G -smp 16 \
  -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type":"vsock","cid":"2","port":"4050"}}' \
  -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off \
  -bios /usr/share/ovmf/OVMF.fd \
  -nographic -nodefaults \
  -drive file=tapp.qcow2,if=none,id=virtio-disk0      -device virtio-blk-pci,drive=virtio-disk0 \
  -drive file=tapp-data.qcow2,if=none,id=virtio-disk1 -device virtio-blk-pci,drive=virtio-disk1 \
  -device virtio-net-pci,netdev=nic0 \
  -netdev user,id=nic0,hostfwd=tcp::10022-:22,hostfwd=tcp::50051-:50051 \
  -serial file:td-serial.log
```

`quote-generation-socket` is the line that matters most: it is how the TD reaches QGS on the host
(`cid=2` is the host). Without it the guest produces a TDREPORT that never becomes a quote.

Four things to get right:

- **Exactly one non-boot disk.** `tapp-data-provision.service` formats and labels "the single
  non-boot disk" and *refuses to guess* with zero or more than one — and docker/containerd are
  `RequiresMountsFor=/data`, so they fail loud rather than writing to the RAM root. Never attach a
  cloud-init seed as a *disk*; as a `-cdrom` it appears as `sr0` and is correctly skipped.
- **Memory is your writable `/`.** The rootfs overlay is RAM-backed zram, so `/` ≈ 4 GB of baked
  base plus whatever you pass to `-m`. More `/` means more `-m`, not a bigger boot disk — and
  anything written to `/` competes with the workload. Persistent state belongs on `/data`.
- **No debug.** `policy.rego` requires `td_attributes.debug == false`; a TD launched with debug on
  fails verification with an error that looks nothing like the cause.
- **Serial is your console.** `HARDEN=1` masks the getty, so a hardened image has no serial login —
  but the boot log still goes to `-serial`, and it is the only view you get if the network or sshd
  never comes up. It is more reliable than SSH during bring-up for exactly that reason.

## 4. Bring tapp up

```bash
tapp-cli -s http://127.0.0.1:50051 -k 0x<owner-key> claim-config
tapp-cli -s http://127.0.0.1:50051 -k 0x<owner-key> start-app --app-id <id> --compose-file app.yml
tapp-cli -s http://127.0.0.1:50051 verify-app --app-id <id> --as-pubkey 0x<as-tls-key-sha256>
```

`claim-config` doubles as the RTMR-extend test: it is a measured operation, so if it succeeds the
guest kernel's TDX measurement interface works. Then `update-node-onchain` if the node is
registered — signers are re-derived every boot, so a restarted TD no longer matches its on-chain
registration (**not verified here**; the verified host had no chain configured).

Gotchas met on the way:

- **The registry must be reachable from inside the TD.** From `cn-beijing`, Docker Hub is not:
  `Get "https://registry-1.docker.io/v2/": connection refused`, and `start-app` fails on the pull.
  Use a regional registry (`registry.cn-beijing.aliyuncs.com/…`) or a mirror.
- **App IDs have a minimum length** — `bm` is rejected as `Invalid app ID format`.
- **`x-tapp.data`**: with no KMS configured, an app whose data mode is the default `encrypted`
  fails to start (by design — no silent plaintext downgrade). Declare `plain`, `ram` or `scratch`
  for an app that must start without one.
- **cryptpilot logs an IMDS failure and continues** — `Failed to connect to Aliyun IMDS endpoint
  (100.100.100.200:80)`. Expected: a self-launched TD is not an ECS instance. It only means no
  cloud-init config was found.
- `systemd-networkd-wait-online` and `systemd-tpm2-setup` fail in the boot log. **Pre-existing** —
  production cloud nodes log the same, so they are not a bare-metal symptom.

## 5. What this buys, and what is still yours

A bare-metal TD is **indistinguishable from a cloud one to a verifier**. The same image measured
identically on a GCP confidential VM (Google's hypervisor) and on this host (our own QEMU):

```
measurement.uki.SHA-384 = b0a640cae384dddec09ae1b683ab966bac83edd2d23bba972074227cbe36d5e85a4bb47a0c35505f179bdb10ad0741de
```

That is the point of TDX's threat model: the host operator is untrusted, so becoming the host
operator yourself does not weaken what you can prove to anyone else. It does not strengthen it
either — the quote is what it is.

What running the host does hand you:

- **TCB currency.** Nobody else is watching it. Monitor the `tcb_status` your nodes report and alert
  on a change; the failure mode is silent (verification simply starts failing) and the fix may not
  be yours to apply.
- **TD lifecycle.** A `systemd` unit is enough for one CVM per machine — tapp's own gRPC handles
  every deployment after boot, so there is no scheduler to write. Give it one non-obvious duty: a
  restarted TD re-derives its signer, so auto-restart without re-running `update-node-onchain`
  leaves a node that is up, listening, and silently stale on chain. A full VMM only becomes
  necessary with multiple mutually-distrusting tenants or multiple machines to schedule across.
- **Physical security**, and the BMC. Both sit outside the TD's trust boundary, so neither breaks
  the attestation — but whoever holds the BMC can stop your node.

## Not yet verified

- `update-node-onchain` after a TD restart (no chain configured on the verified host)
- KMS-backed encrypted data volumes (none configured; the test app used `x-tapp.data: ram`)
- Sysbox under a real multi-tenant workload on this kernel
- **Whether the measurement survives a QEMU upgrade.** dstack hit a case where `RTMR[1]` depended
  on the QEMU version ([Dstack-TEE/dstack#1185](https://github.com/Dstack-TEE/dstack/issues/1185)).
  Ours boots from disk rather than `-kernel`, so that specific bug may not apply — but the class
  does, and on bare metal the QEMU version is yours to change. Worth testing before a host upgrade:
  same qcow2, newer QEMU, does `verify-app` still pass?
- GPU confidential computing — `ebmg8i` has none. See the GPU notes in the main README.
