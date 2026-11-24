# keeper

Permissionless keeper that keeps Google's and Telegram's JWT signing keys
trusted on chain: it obtains MPC-TLS notarized readings of each issuer's JWKS
from a libid notary and submits `rotate()` to its roots contract
(`GoogleJwtRoots`, `TelegramJwtRoots`) on every configured network, paying
the Notary Fee. A network names its roots contracts as `google_jwt_roots`
and `telegram_jwt_roots`, inline or in its chain-configurations file's
`[contracts]`; the keeper serves the issuers a network has.

Telegram compresses some JWKS replies even when the request asks for none,
and the contract refuses an encoded reply. The keeper ends such a session
before the notary signs and reads again, a bounded number of times.

Configuration is one `keeper.toml`; the container image and how to run it
are described in `Dockerfile`.

## End-to-end test

The real rotation path: the published notary image, the contract stack
`libid-deploy` lays down on anvil, and Google's live key set. `compose.yaml`
is the stack; the test runs on the host and reads `e2e/local-dev.toml`,
chain-configurations' published network file unmodified, through the
keeper's own `network_file`. That file names the chain by its compose
service name, so the test's entry sets `rpc_url` to the port compose
publishes on the host.

Needs Docker with Compose v2.7 or later (`up --wait` over a one-shot
service), a Rust toolchain, and network to Google.

```sh
docker compose up -d --wait --build
cargo test --test e2e_real -- --ignored --nocapture
docker compose down                                # a fresh chain per run
```

CI runs the same commands (`.github/workflows/ci.yml`, job `e2e`). When
something fails, `docker compose logs` has every service's output.
