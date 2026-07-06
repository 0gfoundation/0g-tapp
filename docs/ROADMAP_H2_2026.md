# 0G TAPP · TEE Trusted-Application Platform — H2 2026 Roadmap

**Planning window:** Q3 (Jul–Sep) → Q4 (Oct–Dec), 2026
**Legend:** 🟠 In progress ｜ ⚪ Planned ｜ 🟢 Foundation in place

---

## ◆ North Star

Move tapp from a manually-assembled, single-platform deployment to a
production-grade platform: **automated releases, layered/trusted access, and
multi-platform ready.**

---

## Milestones (ordered by dependency)

### ① Immediate wrap-up — early Q3

Quick wins that unlock two pipelines at once.

- 🟠 Ship local-socket access to production — enables the layered access model
  (local vs. external).
- 🟠 Fix the release-tagging bug that currently blocks the CI release pipeline.

### ② Lay the release foundation — Q3 (focus of the quarter)

Today a release is three pieces — binary, VM image, and attestation reference
values — bound together by hand. Automate and connect them.

- ⚪ Bring VM image builds into the repo and CI: versioned, reproducible images.
- ⚪ **[KEYSTONE]** Auto-generate attestation reference values at build time and
  bind them to each release — removing today's manual step.
- 🟢 Binary build pipeline — already reproducible and signed.

### ③ Close the loop — Q3 → Q4

- ⚪ A single release manifest that ties binary + image + attestation values
  together, so any deployment can be verified against it automatically.
- ⚪ Finalize the access model: clear separation of local vs. external calls,
  unified authorization, and a documented access contract.

### ④ Expand to more TEE platforms — Q4

Built on top of ②'s automation.

- ⚪ Introduce a platform-abstraction layer (attestation & verification), with
  the current Intel TDX as the first implementation.
- ⚪ Add AMD SEV-SNP as the second platform, reusing the same release &
  reference-value framework.

---

## ⟺ Cross-cutting · Ops & Robustness (ongoing, not a milestone)

- ⚪ Operator toolset: one-shot health check, better observability, and audit
  logging of key actions.
- ⚪ App log persistence + rotation, so high-log apps can't fill the node disk.
- ⚪ Node resilience: disk-health alerting, crash/OOM restart policy, and
  resource limits.

---

## Critical path

```
local-socket wrap-up ＋ attestation-value automation
    → release manifest
        → AMD SEV-SNP
```

Attestation-value automation is the spine: it removes today's manual work and
is the foundation multi-platform support builds on.
