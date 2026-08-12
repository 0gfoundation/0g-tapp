# Attested TLS for an application

An application running on tapp can serve HTTPS with a certificate whose public key the
attestation evidence commits to. A client that compares the key it was offered during the
handshake against that evidence learns something no certificate authority can tell it: **the
endpoint I am talking to is this TEE, running this code.**

This document is the recipe. It works with an unmodified `nginx`, `envoy`, or anything else
that can be pointed at a key file and a certificate file — the application never learns that
tapp exists.

There are two ways to get the certificate, and they are not alternatives — the same key can
carry both, so one endpoint satisfies a verifier and a browser at once:

| | the certificate | who accepts it |
|---|---|---|
| **self-signed** (below) | issued by the node, for `<app-id>.tapp.0g.ai` | anything checking the key against the attestation — no CA needed |
| **[public CA](#a-certificate-from-a-public-ca)** | issued by Let's Encrypt or your own CA, for a name you choose | browsers and anything else driving off a trust store |

## The shape

The application does not fetch its own certificate. A sidecar does, writes two PEM files into
a shared volume, and exits; the application waits for it and then reads ordinary files.

Fetching means speaking gRPC over a Unix socket. Putting that in a sidecar keeps it out of the
application, which is why this works for software you did not write.

```yaml
services:
  # Fetches this app's attested certificate and exits.
  tls-init:
    # Pin a version, never :latest — this container hands your app its private key.
    # v0.4.0 is a floor, not a lockstep: it talks to any later tapp-server.
    image: us-central1-docker.pkg.dev/g-devops/zg-tapp/tls-init:v0.4.0
    command:
      - --server=/run/tapp/tapp.sock
      - get-app-tls-cert
      - --app-id=my-app                 # must match --app-id passed to start-app
      - --out-key=/certs/tls.key
      - --out-cert=/certs/tls.crt
    volumes:
      - /run/tapp/tapp.sock:/run/tapp/tapp.sock   # the only contact with tapp
      - /run/my-app-certs:/certs                  # /run is tmpfs — see Rules

  web:
    image: nginx:1.27-alpine            # unmodified
    depends_on:
      tls-init:
        condition: service_completed_successfully
    ports:
      - "8443:443"
    volumes:
      - /run/my-app-certs:/etc/nginx/certs:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/certs/tls.crt;
    ssl_certificate_key /etc/nginx/certs/tls.key;
    location / { return 200 "attested\n"; }
}
```

Deploy it like any other app — `tapp-cli start-app -f docker-compose.yaml --app-id my-app`.
`./nginx.conf` is uploaded automatically because it appears in `volumes:`.

Both sides need **v0.4.0 or later**: that is the version that introduced `GetAppTlsCert`.
An older `tapp-server` answers `Unimplemented`, which is easy to misread as a broken sidecar.

### Or build the sidecar yourself

The image is `debian:bookworm-slim` with `tapp-cli` copied in — seventeen lines, at
[`docker/tls-init/Dockerfile`](../docker/tls-init/Dockerfile). It is unsigned, so for a
container that handles your private key, building it yourself is the better option:

```bash
cp target/release/tapp-cli docker/tls-init/
docker build -t tls-init:local docker/tls-init/
```

Nothing in the recipe depends on where the image comes from.

## Rules

**Share the certificate through a path under `/run`, and nowhere else.**

```yaml
      - /run/<app-id>-certs:/certs                    # in the sidecar
      - /run/<app-id>-certs:/etc/nginx/certs:ro       # in the application
```

`/run` is tmpfs, so the key stays in memory the TEE protects. A Docker named volume would put
it in `/data`, which is plain unencrypted ext4 — readable by anyone who can snapshot the disk,
and the end of the platform's guarantee that an application's private key cannot be extracted.
A tmpfs-backed named volume (`driver_opts: {type: tmpfs}`) is not a substitute: each container
gets its own, so the application finds an empty directory.

**Keep `condition: service_completed_successfully`.** It is what makes the application wait for
the certificate instead of starting without one.

**Let the sidecar run on every start.** It re-fetches, which is required: a `local` key is
re-derived at each boot, so a cached certificate stops matching the attestation.

**Match `--app-id` to the app's real id.** The certificate is derived per app; another id
yields a key that is attested for something else.

**Open the TLS port in the cloud firewall too,** not only in `ports:`.

## How a client verifies

The certificate is self-signed and that is correct, not a compromise: what a verifier checks is
the public key against the attestation, not the issuer. A CA would only matter to clients that
will not do that check, such as browsers driving off a system trust store.

Take the key hash from the endpoint:

```bash
openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256
```

and compare it against the attested value, which `verify-app` prints for you:

```bash
tapp-cli -s http://HOST:50051 verify-app --app-id my-app
#   tls key : 0xf714c426…  (sha256 of the public key, attested)
```

Equal means the connection terminates inside the TEE whose evidence you just checked. This is
the whole of layer-1 verification, and it needs no CA.

## Choosing the key source

`tls_key_source` decides where the private key comes from, and the two options trade the same
property in opposite directions. It is set at claim time
(`claim-config --tls-key-source local|kms`) or in `config.toml`.

| | derived from | survives a restart | what the evidence then says |
|---|---|---|---|
| `local` (default) | this CVM's own signer, which never leaves it | **no** — re-derived every boot | "the endpoint is *this TEE instance*" — the strongest statement available |
| `kms` | `(app_id, "tls")` at the KMS cluster | yes, and identical on every node of the app | "some TEE of this app" |

Certificate pinning, Certificate Transparency monitoring and ACME renewal all need a key that
outlives a restart, so they need `kms`. `local` involves nothing external — no KMS, no on-chain
registration — so it works from first boot, which is why it is the default. Stability is what
you opt into once something needs it.

A `kms` key additionally requires the app registered on chain and the cluster reachable, and
shortly after a fresh registration the cluster may answer `401` until its own view of the chain
catches up ([0g-kms#11](https://github.com/0gfoundation/0g-kms/issues/11)).

> **`local` is not merely the default for some services — it is the only option.** Deriving a
> `kms` key means reaching the KMS cluster over the network. Any service that the cluster
> itself depends on, and the cluster's own nodes, therefore cannot use `kms`: they would need
> a working connection in order to be able to serve one. `local` derives from the node's own
> in-TEE signer and touches nothing external, so it works from first boot.
>
> The cost, which such a service has to plan for: its public key changes on every restart, so
> anything pinning it must look the pin up rather than hold a configured copy.

## A certificate from a public CA

Everything above serves a self-signed certificate, which is right for a client that checks the
attested key and wrong for one that checks a trust store. Browsers are the second kind. The two
are not alternatives to choose between: **the same key can carry both**, and then one endpoint
satisfies a browser and a verifier at once.

The rule is **change the name, keep the key**. A certificate may be issued for any name you
control; the public key must not change, because that is what the attestation commits to.

`GetAppCsr` produces the signing request, and unlike `GetAppTlsCert` it is **public** — a
signing request publishes a public key, a name, and a signature proving possession of the
private half, all of which the resulting certificate publishes anyway. It works over TCP, needs
no socket, and needs no key:

```bash
tapp-cli -s http://<node>:50051 get-app-csr \
  --app-id my-app --domain api.example.com --out my.csr
```

**The app does not have to exist yet.** The key is derived from the app id, so a signing request
can be obtained — and a certificate issued — before anything is deployed. That ordering is what
makes this workable: the certificate is ready before the container that needs it starts.

Take `my.csr` to any ACME client in CSR mode. With [lego](https://github.com/go-acme/lego):

```bash
lego --accept-tos --email you@example.com \
     --csr my.csr --http --http.port :80 run
```

Note what is *not* in the output directory: a private key. An ACME client in CSR mode signs the
request you gave it and never generates or sees a key, which is the property that lets a TEE
hold one a CA will still certify.

Then serve the issued certificate with the key the sidecar fetches:

```yaml
  web:
    volumes:
      - /run/my-app-certs:/certs:ro                       # tls.key, from the sidecar
      - ./fullchain.pem:/etc/nginx/fullchain.pem:ro       # from the CA, uploaded with the compose
```

```nginx
ssl_certificate     /etc/nginx/fullchain.pem;   # the CA's
ssl_certificate_key /certs/tls.key;             # the TEE's
```

The certificate is public, so shipping it in the compose directory is fine — `start-app`
uploads it like any other mounted file. Renewal needs `nginx -s reload`, not a restart.

That nginx starts at all is itself a check: a certificate and key that did not match would be
refused outright.

### This wants `kms`

A `local` key is re-derived on every boot, so a CA-issued certificate stops matching the moment
the node restarts, and every reboot means another issuance — which Let's Encrypt's rate limits
(five per week for a set of names) will not tolerate. It is not impossible with a private CA
that can reissue unattended, but a public CA effectively requires `kms`.

### Anyone can request one, and it does not matter

`GetAppCsr` is public, so anyone can obtain a request carrying your app's public key for a
domain *they* control, and have a CA sign it. The result is useless to them: a certificate only
serves TLS in the hands of whoever holds the private key, and completing a handshake requires
signing with it.

Nor does it affect anyone reaching your domain. A certificate is presented by the server you
connected to, not looked up in a directory, so theirs never reaches a client that DNS sent to
you. The one real consequence is noise in Certificate Transparency logs — an entry binding your
key to a domain you do not run. CT is an after-the-fact record that no client consults during a
handshake, so it misleads a human reading logs and nothing else.

**One implementation warning follows from this.** Their certificate does carry your attested
key, so a "verifier" that fetches a certificate and compares its public key *without requiring
the handshake to succeed* would accept it. What stops the attack is that they cannot complete
the handshake. So the comparison must be part of a completed connection:

| how it is checked | safe |
|---|---|
| `curl --pinnedpubkey` — returns only on a completed handshake | yes |
| a rustls verifier — runs during the handshake, which also verifies the signature | yes |
| fetch a certificate, hash its key, compare, ignore whether the handshake finished | **no** |

## Getting the certificate some other way

`GetAppTlsCert` is served **only on the Unix socket** — over TCP it is refused, including from
`localhost` and from a container using `host.docker.internal`. Any process that can open the
socket can read every app's key material, so do not bind-mount it into a container you do not
trust.

If an application would rather call the RPC itself than use the sidecar, the response carries
`key_pem`, `cert_pem`, `csr_pem`, `public_key_sha256` and `key_source`; see
`proto/tapp_service.proto`.

The `csr_pem` in that response is fixed to `<app-id>.tapp.0g.ai`, which a public CA will refuse
because ACME requires the request's names to match the order. Use `GetAppCsr` for a name of your
own — it is public, so it does not drag the socket into certificate renewal.
