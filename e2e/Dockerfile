# The `deploy` service of ../compose.yaml: libid-deploy, chain-configurations'
# deploy tool, converging the compose anvil onto local-dev.toml.
#
# Two things come from ONE pinned chain-configurations release: the tool's
# binary (checksummed per architecture) and the release's
# networks/local-dev.toml. The local-dev.toml committed next to this file is
# that file, byte for byte — the copy the host-side test reads — and `cmp`
# below fails the build if the two ever differ, so the copy is provable
# rather than promised. To move to a new release: bump the version and the
# two checksums here, replace the committed copy, and the build tells you
# if you forgot one.
ARG CHAIN_CONFIGURATIONS_VERSION=0.12.0

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS fetch
ARG CHAIN_CONFIGURATIONS_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl
WORKDIR /fetch
# The tarball's sha256 per release asset; the release page lists them.
RUN set -eu; \
    case "$TARGETARCH" in \
        amd64) triple=x86_64-unknown-linux-gnu; \
               sha256=fab517471598f8fc299e75da2f03e1a528d045ce4483f67edf36284e5b317ad6 ;; \
        arm64) triple=aarch64-unknown-linux-gnu; \
               sha256=620b7e98c9eea205b9501b5b051b887b0b971bb2c005979792c741dd603c1d5e ;; \
        *) echo "no libid-deploy release for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    repo="https://github.com/libid-org/chain-configurations"; \
    tarball="libid-deploy-${CHAIN_CONFIGURATIONS_VERSION}-${triple}.tar.gz"; \
    curl -fsSL -o "$tarball" \
        "${repo}/releases/download/v${CHAIN_CONFIGURATIONS_VERSION}/${tarball}"; \
    echo "${sha256}  ${tarball}" | sha256sum -c -; \
    tar xzf "$tarball"; \
    mv "libid-deploy-${CHAIN_CONFIGURATIONS_VERSION}-${triple}/libid-deploy" .; \
    curl -fsSL -o release-local-dev.toml \
        "https://raw.githubusercontent.com/libid-org/chain-configurations/v${CHAIN_CONFIGURATIONS_VERSION}/networks/local-dev.toml"
COPY local-dev.toml local-dev.toml
RUN cmp release-local-dev.toml local-dev.toml

# The same runtime base, at the same digest, as the keeper's own image.
# ca-certificates: the tool's HTTP client refuses to build without a CA
# store, even though the only endpoint it reaches here is plain http.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /fetch/libid-deploy /usr/local/bin/libid-deploy
COPY --from=fetch /fetch/local-dev.toml /e2e/local-dev.toml
ENTRYPOINT ["libid-deploy"]
