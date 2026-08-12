# Production image for the libID JWKS keeper: polls Google, notarizes via MPC-TLS, rotates on-chain roots.
#
# Pin the builder to bookworm so its glibc matches the bookworm-slim runtime
# stage below. A bare `-slim` tag floats to newer Debian (trixie), producing
# binaries that need GLIBC_2.38+ and fail on bookworm (glibc 2.36) at runtime.
FROM rust:1.97-slim-bookworm AS builder

# git: the libid-rs and tlsn dependencies are git sources.
RUN apt-get update && apt-get install -y pkg-config libssl-dev git && rm -rf /var/lib/apt/lists/*

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
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/keeper /usr/local/bin/keeper


ENTRYPOINT ["keeper"]
