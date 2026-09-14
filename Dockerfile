# Production image for the libID JWKS keeper: polls Google, notarizes via
# MPC-TLS, rotates on-chain roots.
#
# The whole runtime contract is one file, mounted read-only where
# KEEPER_CONFIG points (see the ENV below):
#
#   docker run --rm \
#     -v "$PWD/keeper.toml:/etc/keeper/keeper.toml:ro" \
#     ghcr.io/libid-org/keeper:<version> run
#
# `status` and `once --dry-run` need only `[[networks]]`; `run` and `once`
# also need `notary_url` and a `signer`, and refuse to start without them.
# Mount the directory instead of the file when keeper.toml references
# chain-configurations network files: they resolve relative to it. A KMS
# signer takes its credentials from the usual AWS environment (IRSA on EKS,
# or AWS_* variables).
#
# Every tag is a manifest list for linux/amd64 and linux/arm64, so the same
# reference runs on GitHub's runners, on x86 and Graviton nodes, and on Apple
# Silicon without a --platform flag. Both base images are pinned by the digest
# of their multi-platform index, so the pin covers every architecture.
#
# Pin the builder to bookworm so its glibc matches the bookworm-slim runtime
# stage below. A bare `-slim` tag floats to newer Debian (trixie), producing
# binaries that need GLIBC_2.38+ and fail on bookworm (glibc 2.36) at runtime.
FROM rust:1.98.1-slim-bookworm@sha256:ebd900bae66fd508b466cef82d64a83a5fb34682e4c8b2797a42908bddc95a57 AS builder

# git: the libid-rs and tlsn dependencies are git sources. Nothing else is
# needed — the TLS stack is rustls (aws-lc-sys/ring), so there is no
# openssl-sys in the graph.
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Layer 1: cache dependency compilation ──────────────────────────────────
# Copy only the manifests first: the (large, slow) dependency graph rebuilds
# only when Cargo.toml/Cargo.lock change, not on every source edit.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && touch src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --locked --release
# Remove the stub crate's artifacts so it rebuilds from real source.
RUN rm -rf src \
    && rm -f target/release/keeper \
    && rm -rf target/release/deps/keeper-* target/release/deps/libkeeper-* \
        target/release/.fingerprint/keeper-*

# ── Layer 2: real source — only rebuilds this crate ────────────────────────
COPY src/ src/
RUN cargo build --locked --release

# === Runtime ===
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# ca-certificates: outbound TLS to Google, to every configured RPC, and to AWS
# KMS when a signer is a key id. libssl3 is deliberately not named: nothing
# links it — `ldd` on the binary lists libc, libm and libgcc_s only.
# ca-certificates still pulls it in through openssl, so dropping the explicit
# install does not shrink the image; it stops the Dockerfile claiming a
# dependency this binary does not have.
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/keeper /usr/local/bin/keeper

# The keeper writes nothing and listens on nothing, so it has no reason to be
# root. A fixed uid/gid keeps behaviour stable for the one thing a deployment
# does mount: its keeper.toml.
RUN groupadd --system --gid 10001 keeper \
    && useradd --system --uid 10001 --gid keeper --no-create-home --shell /usr/sbin/nologin keeper
USER 10001:10001

# Where a deployment mounts its config. `--config` defaults to a RELATIVE
# `keeper.toml`, which in a container resolves against `/`; naming the path
# absolutely makes `-v ./keeper.toml:/etc/keeper/keeper.toml` the whole recipe.
ENV KEEPER_CONFIG=/etc/keeper/keeper.toml

# No EXPOSE and no HEALTHCHECK: the keeper serves nothing. `keeper once` exits
# nonzero when a tick failed, which is the health signal a scheduler reads;
# `keeper run` is a long process whose liveness is its exit code.

# Links the ghcr package to this repo and records what the image came from.
LABEL org.opencontainers.image.source="https://github.com/libid-org/keeper" \
      org.opencontainers.image.description="libID JWKS keeper: notarized readings of Google's JWKS, rotated into GoogleJwtRoots on every configured chain." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["keeper"]
