# TAPP Roadmap — H2 2026

## Objective

Turn tapp from a manually-assembled, single-platform deployment into an **automated-release, layered-trust, multi-platform, integratable platform** — without weakening the TEE security baseline.

Three phases, built sequentially:

1. **Consolidate** (M1) — finish the in-flight interface work, lock versioning & compatibility, and unblock the release pipeline.
2. **Automate the release** (M2–M4) — bring CVM image builds and attestation reference values under CI, tie the three release artifacts into one verifiable manifest, and harden node operation.
3. **Open up** (M5–M6) — add a second TEE platform and expose tapp through a stable SDK.

> **Sequencing principle:** decisions that are expensive to reverse (versioning & compatibility rules, the attestation-reference-value framework, the platform abstraction, the SDK interface) are locked first. Everything else is additive.

---

## Current Gaps (why we need this roadmap)

| Area | Risk | Impact |
|------|------|--------|
| **Release binding** | Binary + CVM image + attestation reference values are bound together by hand | No traceability; a running deployment can't be verified against a known release |
| **Reference values** | `kernel_cmdline` and measurements are maintained manually | Drift and human error; blocks onboarding any second platform |
| **CI release pipeline** | Workflow triggers on `v*`, which never matches the documented `tapp-server-v*` tags | Tagging per the docs never builds a release |
| **Single TEE platform** | TDX-only across build, attestation, and verification | Cannot onboard AMD SEV-SNP or other hardware |
| **Developer access** | Only `tapp-cli`; no SDK | High integration barrier; every interface change risks breaking integrators |
| **Call-model boundary** | Sensitive local operations historically gated only by client IP | Weak trust boundary for local key/secret retrieval |
| **Node robustness** | App logs are unbounded — no persistent directory, no rotation | A high-log app can fill the node disk and take it down |
| **Observability** | No health self-check, metrics, or audit log | Hard to operate a fleet; problems are found by humans, not systems |

---

## Milestones

| Milestone | Theme | Deliverables | Status |
|-----------|-------|-------------|--------|
| **M1** | Consolidate interfaces | Unix-socket to production (S1) · Versioning policy + runtime compatibility check (S2) · Fix CI tag trigger (S3) | In progress |
| **M2** | Automate the release | Repo-ized, reproducible CVM image build (S4) · Attestation-reference-value automation (S5) | Planned |
| **M3** | Close the release loop | Release manifest reconciliation (S6) · Lock access model + authorization contract (S7) | Planned |
| **M4** | Harden & operate | Ops toolset — health self-check, metrics, audit log (S8) · App log persistence + rotation (S9) · Node resilience (S10) | Planned |
| **M5** | Expand platforms | Attestation/verification platform abstraction (S11) · AMD SEV-SNP implementation (S12) | Planned |
| **M6** | Open up | `tapp-common` hardened + published as an SDK (S13) · Language bindings (S14) · Examples + quickstart (S15) | Planned |

> **M1 status:** unix-socket support (S1) is merged; the versioning policy and runtime compatibility check (S2) are in review; the CI tag-trigger fix (S3) is a small pending change.

---

## Strategic Choices

**Lock interfaces and compatibility before opening up.** The versioning scheme and the CLI ↔ server ↔ contract compatibility rules (M1, S2) are commitments to every downstream consumer — the CLI, the SDK, and third-party integrators. Once an SDK (M6) is published, changing its shape breaks everyone who built on it. We lock the rules first so later changes are additive (new RPCs, new fields, new bindings) rather than breaking. Reference lesson from sibling projects: interface churn makes clients non-migratable — we avoid that by design.

**Reference-value automation is the spine.** Today `kernel_cmdline` and measurements are hand-maintained. Automating their generation and binding them to each release (M2, S5) both removes that manual toil and is the prerequisite for a second platform — every TEE platform needs its own set of measurements produced the same way. That is why M2 comes before M5.

**A release is three coupled artifacts.** Binary + CVM image + reference values are released together but bound by hand today. We automate binding them into one machine-readable, verifiable manifest (M2–M3) before scaling to more platforms, so each new platform plugs into an existing, reconcilable pipeline instead of more manual coordination.

**gRPC and on-chain are separate compatibility edges.** The versioning rules treat the CLI ↔ server gRPC contract and the (server/CLI) ↔ contract ABI as independent edges, each with its own interface version read at runtime. The KMS/contract layer and the service can therefore evolve on separate tracks.

**Defer what's uncertain.** A second TEE platform (M5) depends on hardware availability and per-platform attestation-service work; multi-language SDK bindings and node federation carry open questions. We commit the core (the abstraction layer and the Rust SDK) and let the rest slip past H2 if needed.

**Robustness runs throughout, but disk safety is real.** Ops tooling and resilience (M4) span every milestone, but unbounded app logs are a concrete availability risk — a single noisy app can fill a node's disk — so log persistence and rotation are committed, not deferred.

---

## Scope

**Committed (H2):** S1 unix-socket · S2 versioning + compatibility check · S3 CI tag fix · S4 CVM image build · S5 reference-value automation · S6 release manifest · S8 ops toolset · S9 log persistence + rotation · S11 platform abstraction · S13 SDK core

**Designed now, may extend beyond H2:** S12 AMD SEV-SNP (node onboarding + attestation-service work) · S14 multi-language SDK bindings · S10 advanced node resilience (disk-watermark self-heal, resource governance) · S7 advanced authorization · full multi-platform reproducible-build CI matrix
