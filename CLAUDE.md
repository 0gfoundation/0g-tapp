# Working in this repository

Conventions that are not discoverable from the code, and that cost real time when missed.

## Finish a change properly

A change is not done when it compiles. Two things are part of it:

**Bump the version** per [`docs/VERSIONING.md`](docs/VERSIONING.md). Adding an RPC or a proto
field is MINOR; changing a default value or other visible behaviour is PATCH. A tag names a
*release*, not a binary version — one tag can ship tapp-server 0.4.0 alongside tapp-cli 0.4.1, and
bumping a binary that did not change just to line the numbers up is wrong.

**Regress the documentation.** After any interface change, check:

- `.claude/skills/0g-tapp-cli/SKILL.md` — and bump its own `version:` field
- `README.md`
- whichever file under `docs/` covers the area

Do not skim for stale wording. Count: `grep -c '<new-flag>' README.md .claude/skills/*/SKILL.md`.
Twice now that has returned 0 for an entire round of work — the feature existed and no document
mentioned it at all.

This matters more here than in most repositories, because these documents are how other people
and other agents operate the system. Drift is not cosmetic: one round left `README.md` telling
apps to fetch key material over `host.docker.internal:50051` *after* that was made to refuse, and
left `docs/verify_app.py` reading the signer in a format that makes a healthy node report as
failed.

## The proto exists twice

`proto/tapp_service.proto` and `tapp-common/proto/tapp_service.proto` must stay byte-identical and
are **not** synced by any build step. Copy it by hand after every edit and check:

```bash
cat proto/tapp_service.proto > tapp-common/proto/tapp_service.proto
diff -q proto/tapp_service.proto tapp-common/proto/tapp_service.proto
```

(`cp` may prompt interactively and hang a non-interactive shell; the redirect does not.)

## New RPCs need a permission

`src/auth_layer.rs` assigns every method a `MethodPermission`. An unlisted one falls through to
`OwnerOnly`, which usually looks like a working RPC that inexplicably demands a signature. A test
walks the proto and fails on any method without a deliberate entry — if it fails, add the entry
rather than the exception.

## Testing against a real node

Unit tests do not exercise the paths that break. Several real defects this round were only
reachable by running against hardware: a measured event recording configuration the node was not
actually using, a TLS pin checked against the wrong source, an eager derivation that fails
silently whenever the chain has not caught up.

Two things to know before starting:

- **A CVM's root filesystem is a RAM overlay.** Anything installed into `/usr/local/bin` is gone
  after a VM reboot and the node reverts to the binary baked into its image. Re-install after
  every reboot, and do not read "the version went backwards" as a deployment failure.
- **Signers are re-derived on every boot**, so a node that has rebooted no longer matches its
  on-chain registration. Fix it with `update-node-onchain` before anything that authorises against
  the chain — the KMS in particular — or the failure will look like a network problem.
