# Attested TLS for an application

An application running on tapp can serve HTTPS with a certificate whose public key the
attestation evidence commits to. A client that compares the key it was offered during the
handshake against that evidence learns something no certificate authority can tell it: **the
endpoint I am talking to is this TEE, running this code.**

This document is the recipe. It works with an unmodified `nginx`, `envoy`, or anything else
that can be pointed at a key file and a certificate file — the application never learns that
tapp exists.

## The shape

The application does not fetch its own certificate. A sidecar does, writes two PEM files into
a shared volume, and exits; the application waits for it and then reads ordinary files.

That indirection is the point. Fetching means speaking gRPC over a Unix socket, and requiring
every application to grow that client is what makes a pattern "only for apps we wrote".

```yaml
services:
  # Fetches this app's attested certificate and exits.
  tls-init:
    # Pinned deliberately, and it does not need bumping with tapp-server: v0.4.0 is
    # the floor (the version that introduced GetAppTlsCert), not a lockstep. A v0.4.0
    # sidecar talks to a later server fine. Avoid :latest — this container is what
    # hands your application its private key, and it should not change underneath you.
    image: us-central1-docker.pkg.dev/g-devops/zg-tapp/tls-init:v0.4.0
    command:
      - --server=/run/tapp/tapp.sock
      - get-app-tls-cert
      - --app-id=my-app                 # must match --app-id passed to start-app
      - --out-key=/certs/tls.key
      - --out-cert=/certs/tls.crt
    volumes:
      - /run/tapp/tapp.sock:/run/tapp/tapp.sock   # the only contact with tapp
      # A path under /run, which is tmpfs: the private key stays in RAM and never
      # reaches a disk. See "Keep the key off the disk" — this is not a hardening
      # option, it is the difference between the platform's claim about private
      # keys holding and not.
      - /run/my-app-certs:/certs

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
[`docker/tls-init/Dockerfile`](../docker/tls-init/Dockerfile). For a container that handles
your application's private key, building it from a Dockerfile you have read is a stronger
position than trusting one somebody published:

```bash
cp target/release/tapp-cli docker/tls-init/
docker build -t tls-init:local docker/tls-init/
```

Nothing in the recipe depends on where the image comes from.

## Keep the key off the disk

The platform's claim is that an application's private key cannot be extracted, including by
whoever deployed it. Writing that key to a persistent disk gives it away, and the obvious
compose does exactly that: a **named volume lands on `/data`, which is plain ext4 and not
encrypted.** The cryptpilot devices protect the root filesystem, not `/data`. The key sits
there in plaintext at mode 0600 — proof against another user on the box, and no use at all
against anyone who can read the disk or take a snapshot of it.

Bind-mounting a path under **`/run`** is the fix, because `/run` is tmpfs. The key exists only
in memory, which on this platform is memory the TEE protects, and it is gone at reboot — which
is exactly right for a `local` key that gets re-derived at the next boot anyway. Docker creates
the directory for you.

```yaml
    volumes:
      - /run/<app-id>-certs:/certs                    # in the sidecar
      - /run/<app-id>-certs:/etc/nginx/certs:ro       # in the application
```

**A tmpfs-backed named volume does not work, though it looks like it should.** Declaring

```yaml
volumes:
  certs:
    driver_opts: { type: tmpfs, device: tmpfs }
```

gives each container its own tmpfs rather than a shared one. The sidecar writes into its copy,
exits, that mount disappears, and the application starts against an empty directory:

```
[emerg] cannot load certificate "/etc/nginx/certs/tls.crt": ... No such file or directory
```

Which is why the recipe bind-mounts a real path on a filesystem that already is tmpfs, rather
than asking Docker for one.

## Three more things that will bite

**`condition: service_completed_successfully` is not optional.** Without it the web container
starts while `/certs` is still empty and dies on a missing file, then restarts into the same
race. The dependency is what makes the ordering real.

**Open the TLS port.** The compose `ports:` entry is not the whole story on a cloud host; the
firewall has to allow it too. Easy to miss, because everything looks healthy from inside.

**`--app-id` must match the app's real id.** The certificate is derived per app, and asking for
a different id yields a key that is attested — for something else.

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

## Binding a domain name

Nothing above involves a domain. If you need one — because browsers must accept the
certificate — the rule is **change the name, keep the key**. The certificate may be reissued
for any name you control; what must not change is the public key, because that is what the
attestation commits to.

The certificate and the `csr_pem` in the response both carry a fixed name, `<app-id>.tapp.0g.ai`.
So:

- **Your own CA** — use `csr_pem` as it is, or set `ca_url` in `config.toml` and let
  `GetAppTlsCert` return a CA-signed certificate directly. A CA you run does not care what
  name the request asks for.
- **A public CA (Let's Encrypt)** — `csr_pem` is *not* usable: ACME requires the CSR's names to
  match the order, and yours will not be `<app-id>.tapp.0g.ai`. Build a new request from the
  same key instead:

  ```bash
  openssl req -new -key tls.key -subj "/CN=api.example.com" \
    -addext "subjectAltName=DNS:api.example.com" -out my.csr
  ```

  Same `tls.key` means the same public key, so the issued certificate satisfies both checks at
  once: a browser matches the name the CA vouched for, and a verifier matches the key the
  attestation vouched for. They read different fields and do not interfere.

**This effectively requires `kms`.** A `local` key is re-derived every boot, so a CA-issued
certificate is void the moment the node restarts and would need reissuing each time — which
Let's Encrypt's rate limits will not tolerate.

The two layers are independent and the second is optional:

| | what it binds | what the client must do |
|---|---|---|
| evidence | the TLS public key to a TEE — no CA involved | compare the two hashes itself |
| a CA | a name to that same key | nothing; the trust store handles it |

## Getting the certificate some other way

`GetAppTlsCert` is served **only on the Unix socket** — over TCP it is refused, including from
`localhost` and from a container using `host.docker.internal`. Any process that can open the
socket can read every app's key material, so do not bind-mount it into a container you do not
trust.

If an application would rather call the RPC itself than use the sidecar, the response carries
`key_pem`, `cert_pem`, `csr_pem`, `public_key_sha256` and `key_source`; see
`proto/tapp_service.proto`.
