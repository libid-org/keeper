# keeper

Permissionless keeper that keeps Google's JWT signing keys trusted on chain:
it obtains MPC-TLS notarized readings of Google's JWKS from a libid notary
and submits `rotate()` to `GoogleJwtRoots` on every configured network,
paying the Notary Fee. Configuration is one `keeper.toml`; the container
image and how to run it are described in `Dockerfile`.

## End-to-end test

The real rotation path: the published notary image, the contract stack
`libid-deploy` lays down on anvil, and Google's live key set. `compose.yaml`
is the stack; the test runs on the host and reads `e2e/local-dev.toml`,
chain-configurations' published network file unmodified, through the
keeper's own `network_file`. That file names the chain by its compose
service name, so the host maps it once.

Needs Docker with Compose v2.7 or later (`up --wait` over a one-shot
service), a Rust toolchain, `sudo` for the hosts line, and network to
Google.

```sh
echo "127.0.0.1 anvil" | sudo tee -a /etc/hosts   # once per machine
docker compose up -d --wait --build
cargo test --test e2e_real -- --ignored --nocapture
docker compose down                                # a fresh chain per run
```

CI runs the same commands (`.github/workflows/ci.yml`, job `e2e`). When
something fails, `docker compose logs` has every service's output.
