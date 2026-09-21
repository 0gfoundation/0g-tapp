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

## tappscan.0g.ai — the explorer, both networks

| network | URL | chain | registry |
|---|---|---|---|
| testnet | `https://tappscan.0g.ai/` | 16602 | `0x2Ce8…165c9` |
| mainnet | `https://tappscan.0g.ai/?net=mainnet` (API under `/mainnet/`) | 16661 | `0x5487…e612` |

Serves a Let's Encrypt certificate — browsers and plain `curl` verify it with
no pin. The page's network toggle switches between the two instances; the pill
follows the backing instance's `chain_id`, not the URL.

## 35.253.66.70 — the attested instance (anchor + AS)

The original deployment, itself running as a tapp app (**app_id `0g-tappscan`**
on the testnet registry) with **attested self-signed TLS** — its serving key is
committed in its own attestation evidence, which is what makes it pinnable as a
trust anchor:

```
--scan-url    https://35.253.66.70
--scan-pubkey 0x7b13d1320e7ebc93a6edf809d06cf9b44704677461c6feb2c4204e92e5587e9b
```

(The same pin in `curl --pinnedpubkey` form:
`sha256//exPRMg5+vJOm7fgJ0Gz5tEcEZ3Rhxv6yxCBOkuVYfps=`.)

It also fronts the self-hosted **CoCo-AS**, which is `verify-app`'s default:

```
--as-endpoint https://35.253.66.70:50004
```

The AS speaks TLS; a bare `host:port` without a scheme means plaintext and
fails as an h2 protocol error, so always give the scheme.

## Which one to use for what

- Reading attestation state, sharing links, mainnet apps → **tappscan.0g.ai**.
- `claim-config` / `update-trust-anchors` scan anchors → the **attested
  instance's** URL + pin above. An anchor must be a key the node can hold the
  verifier to; a CA-issued certificate rotates at renewal and pins nothing
  durable.
- `verify-app --as-endpoint` → the attested instance's `:50004` (the default).

Like [KMS.md](KMS.md)'s cluster tables, this file tracks deployments, not
truth: what a given instance actually vouches for is recomputed from the chain
and the published reference values on every read.
