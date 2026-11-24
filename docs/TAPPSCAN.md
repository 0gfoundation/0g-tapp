# tappscan: deployed verifier instances

tappscan is the attestation explorer and trust-layer-3 verifier
([source and design](https://github.com/0gfoundation/0g-tapp-verifier)). It
plays three distinct roles, and each role needs a different value from this
page:

1. **Explorer** — a page where anyone reads the attestation state of every
   registered app (which URL to open).
2. **Trust anchor** — the verifier a tapp node believes about KMS cluster
   identity (`claim-config --scan-url … --scan-pubkey …`; see
   [KMS.md](KMS.md)).
3. **Attestation Service host** — the CoCo-AS that `tapp-cli verify-app`
   submits quotes to (`--as-endpoint`).

Apps on a tapp can use **`ResolveAppIdentity`** on its local Unix socket to
query that node's pinned Scan without implementing a Scan client or separately
configuring trust anchors. The RPC requires the chain, TappRegistry, and app id;
see [APP_IDENTITY.md](APP_IDENTITY.md). It requires Scan's structured
`/api/verify` API; it never substitutes the explorer's `/cert` pin list for a
verification verdict.

## The instances — one per network

Each network has its own instance, which watches only that network's registry.
Each runs as a tapp app itself (**app_id `0g-tappscan`** on its own network's
registry) with **attested TLS** — its serving key is committed in its own
attestation evidence, which is what makes it pinnable as a trust anchor. The
Let's Encrypt certificate it serves is issued for that same key, so browsers and
plain `curl` verify it with no pin.

| network | URL (explorer and API) | chain | registry | app owner | TLS pin (`--scan-pubkey`; `curl --pinnedpubkey`) | AS (`--as-endpoint`) |
|---|---|---|---|---|---|---|
| mainnet | `https://tappscan.0g.ai` (VM `35.202.46.28`) | 16661 | `0x54874F536301c993922Dd95097e3902e7FBfe612` | `0xc0603224dE8c3B910a4487368E476e19dC6127cF` (Fordefi multisig vault) | `0xdb845d0b13587b779b30968d019899aa64c6e8afe19acfad84425b020f3aab6c`; `sha256//24RdCxNYe3ebMJaNAZiZqmTG6K/hms+thEJbAg86q2w=` | `https://tappscan.0g.ai:50004` |
| testnet | `https://tappscan-testnet.34-122-75-6.sslip.io` (VM `34.122.75.6`) | 16602 | `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9` | `0x9C58F839451EBf3e7f82442bC48E4088746380Bb` | `0xbd13b2b7a96a788f29c7cf1e17136bc034e3ab4fe3774cb33088dbbeee0e6dd4`; `sha256//vROyt6lqeI8px88eFxNrwDTjq0/jd0yzMIjbvu4ObdQ=` | `https://tappscan-testnet.34-122-75-6.sslip.io:50004` |

As a node's trust anchor, use its own network's instance:

```
--scan-url    https://tappscan.0g.ai                          # mainnet
--scan-url    https://tappscan-testnet.34-122-75-6.sslip.io   # testnet
--scan-pubkey 0x<that network's pin above>
```

This key is generated per boot inside that TEE: when the instance's VM reboots
it changes, and this page is where the new value is published.

## The Attestation Service

Each instance also fronts a self-hosted **CoCo-AS** on `:50004`. The AS is the
same TEE app, so it presents the same key — pin it, or every verdict
`verify-app` prints could come from whoever is on the path (it warns, and never
reports better than ⚠️, without one). An AS judges a quote, not a network, so
either instance's AS verifies the nodes of both; these docs use the mainnet one.
Pass it explicitly: tapp-cli ≤ 0.11.1 defaults `--as-endpoint` to a retired AS.

```
--as-endpoint https://tappscan.0g.ai:50004
--as-pubkey   0x<the mainnet pin above>
# or once, for every run:
export TAPP_AS_ENDPOINT=https://tappscan.0g.ai:50004 TAPP_AS_PUBKEY=0x<the mainnet pin above>
# docs/verify_app.py: AS_ENDPOINT and AS_PUBKEY, the same values
```

The AS speaks TLS; a bare `host:port` without a scheme means plaintext and
fails as an h2 protocol error, so always give the scheme.

> **2026-11-19:** `:50004` on both instances is closed to the internet until an
> nginx fix is rolled out to both; the explorer and the anchors on 443 are not
> affected. Until it re-opens, run a CoCo-AS of your own (the self-hosted stack in
> [TDX_BOOT_CHAIN_VERIFICATION.md](TDX_BOOT_CHAIN_VERIFICATION.md) §5) and pass
> `--as-endpoint 127.0.0.1:50004`; `verify-app` then warns that the AS is not
> authenticated, which for one on your own machine is expected.

## Which one to use for what

- Reading attestation state, sharing links → the URL of the app's network.
- `claim-config` / `update-trust-anchors` scan anchors → the node's network's
  URL + pin above. An anchor must be a key the node can hold the verifier to:
  the pin is the attested key, which changes only when that scan's VM reboots.
- `verify-app --as-endpoint` → `https://tappscan.0g.ai:50004` with its pin, for
  nodes of either network.
- `verify-app` on a node whose port is closed to you fetches its evidence through
  the scan of its registry; tapp-cli ≤ 0.11.1 has outdated scan URLs for that, so
  pass `--relay <the node's network's scan URL>`.

Like [KMS.md](KMS.md)'s cluster tables, this file tracks deployments, not
truth: what a given instance actually vouches for is recomputed from the chain
and the published reference values on every read.
