# The cert-fetching sidecar: tapp-cli, and nothing else.
#
# An application that wants attested TLS should not have to grow a gRPC client to
# get it. This image fetches the certificate into a shared volume and exits, so the
# application container reads two ordinary PEM files and never learns that tapp
# exists — which is what makes the pattern work for an unmodified nginx, envoy, or
# anything else that can be pointed at a key and a cert.
#
# Built from the binary the reproducible build already produced rather than
# compiling again, so the tapp-cli in this image is byte-identical to the released
# one and carries the same signature.
#
# Debian rather than Alpine: tapp-cli links against glibc.
FROM debian:bookworm-slim

# ca-certificates is not for talking to tapp — that is a Unix socket — but for the
# on-chain RPC calls some subcommands make, so the same image serves other uses.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY tapp-cli /usr/local/bin/tapp-cli

# No default subcommand: the compose file states what it wants, and a default here
# would be a second place for that to be decided.
ENTRYPOINT ["/usr/local/bin/tapp-cli"]
