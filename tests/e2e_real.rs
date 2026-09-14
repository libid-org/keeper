//! The whole loop for real: a running notary, the real contracts on Anvil,
//! Google's live JWKS, and one genuine MPC-TLS rotation.
//!
//! `e2e.rs` proves everything but MPC-TLS, with the mock prover as the proof
//! source. This test proves the rest: the keeper's prover runs a real session
//! against `www.googleapis.com` through a notary it does not share a crate
//! with, reads the signed record back off the wire, and `GoogleJwtRoots`
//! accepts it. It is `#[ignore]`d because it needs two things CI does not
//! have by default -- a notary to talk to and network to Google.
//!
//! # Running it
//!
//! Start a notary signing with Anvil's dev key #1 (the key the deployed
//! `NotaryService` is initialized to trust, as in `e2e.rs`), either from a
//! checkout of libid-org/notary:
//!
//! ```sh
//! notary --port 7047 --ws-port 0 \
//!   --signing-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
//! ```
//!
//! or from the published image:
//!
//! ```sh
//! docker run --rm -p 7047:7047 ghcr.io/libid-org/notary:<version> \
//!   --host 0.0.0.0 --port 7047 --ws-port 0 \
//!   --signing-key 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
//! ```
//!
//! then point the test at it:
//!
//! ```sh
//! KEEPER_E2E_NOTARY=127.0.0.1:7047 cargo test --test e2e_real -- --ignored
//! ```
//!
//! # The stack under test
//!
//! With nothing else set, the test deploys `NotaryService` and
//! `GoogleJwtRoots` itself, on an anvil it spawns -- one command, no
//! prerequisites. To drive a stack deployed OUTSIDE it, as CI does with
//! `libid-deploy apply` against a plain anvil, name that stack instead:
//!
//! * `KEEPER_E2E_GOOGLE_JWT_ROOTS=0x…` -- the deployed roots proxy. Setting
//!   it is what selects the external stack; nothing is deployed then.
//! * `KEEPER_E2E_RPC=http://…` -- its chain. Defaults to
//!   `http://127.0.0.1:8545`, where a plain `anvil` listens.
//! * `KEEPER_E2E_NOTARY_SERVICE=0x…` -- the service the fee is paid to. Read
//!   off `GoogleJwtRoots.notaryService()` when unset.
//!
//! An external stack must be fresh -- the test asserts a FIRST rotation --
//! its Notary Service must trust the key the notary signs with, and Anvil's
//! dev key #0 must be funded on its chain, since that key pays gas and the
//! fee.
//!
//! `KEEPER_E2E_NOTARY_ADDRESS=0x…` overrides the trusted notary address when
//! the notary signs with some other key. `KEEPER_E2E_CAPTURE=<path>` also
//! writes the record the keeper obtained -- attested data, signature, the
//! address the signature recovers to and the notary's `createdAt` -- as JSON,
//! which is how a contract test gets a fixture Google actually served.

use std::path::Path;

use alloy::{
    node_bindings::{
        Anvil,
        AnvilInstance,
    },
    primitives::{
        Address,
        U256,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
};
use keeper::{
    config::KeeperConfig,
    decision,
    proof::ProofSource,
    run,
};
use libid_contracts::{
    artifacts::Artifacts,
    bindings::ceremony::{
        GoogleJwtRoots,
        NotaryService,
    },
    deploy::deploy_behind_proxy,
};
use libid_crypto::{
    hex_to_signing_key,
    pubkey_to_eth_address,
    recover_eth_claim,
};
use libid_signer::SignerSource;

/// Anvil's dev key #0 -- pays gas and the Notary Fee.
const GAS_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Anvil's dev key #1 -- the key the notary under test is expected to sign
/// with, so the deployed `NotaryService` trusts it. Same convention as the
/// mock in `e2e.rs`.
const NOTARY_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// The Notary Fee the service is deployed with. Non-zero so a rotation that
/// forgot to attach it reverts, and so the fee's arrival can be asserted.
/// An external stack sets its own; the fee is read off the chain either way.
const NOTARY_FEE_WEI: u64 = 1_000;
/// Where a plain `anvil` listens: the default chain for an external stack.
const DEFAULT_RPC: &str = "http://127.0.0.1:8545";
/// Google's live key set -- the same endpoint the notarized session reads.
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

fn write_keeper_toml(dir: &Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("keeper.toml");
    std::fs::write(&path, contents).unwrap();
    path
}

/// The notary this run talks to, from `KEEPER_E2E_NOTARY`. A missing variable
/// is a usage error, not a skip: the test only runs when asked for.
fn notary_under_test() -> String {
    std::env::var("KEEPER_E2E_NOTARY").expect(
        "set KEEPER_E2E_NOTARY=host:port to a running notary that signs with \
         Anvil's dev key #1 (see the module docs), then run with --ignored",
    )
}

/// The address the deployed `NotaryService` trusts: Anvil #1 by default, or
/// `KEEPER_E2E_NOTARY_ADDRESS` when the notary signs with another key.
fn trusted_notary_address() -> Address {
    env_address("KEEPER_E2E_NOTARY_ADDRESS").unwrap_or_else(|| {
        Address::from(pubkey_to_eth_address(
            hex_to_signing_key(NOTARY_KEY).unwrap().verifying_key(),
        ))
    })
}

/// The `0x…` address in `var`, when it is set. A malformed one is a usage
/// error, not a reason to fall back to a default nobody asked for.
fn env_address(var: &str) -> Option<Address> {
    std::env::var(var)
        .ok()
        .map(|hex| hex.parse().unwrap_or_else(|e| panic!("{var}: {e}")))
}

/// The chain the contracts live on. An external stack names its own RPC (or
/// takes the default anvil endpoint); otherwise this test spawns the chain
/// and holds it open for the run.
fn chain_under_test(external: bool) -> (Option<AnvilInstance>, String) {
    if external {
        let rpc =
            std::env::var("KEEPER_E2E_RPC").unwrap_or_else(|_| DEFAULT_RPC.to_string());
        return (None, rpc);
    }
    assert!(
        std::env::var_os("KEEPER_E2E_RPC").is_none(),
        "KEEPER_E2E_RPC names a chain but KEEPER_E2E_GOOGLE_JWT_ROOTS names \
         no contract on it: set both to drive a deployed stack, or neither to \
         deploy on a spawned anvil"
    );
    let anvil = Anvil::new().spawn();
    let rpc = anvil.endpoint();
    (Some(anvil), rpc)
}

/// Deploy the pair this test drives from libid-contracts' embedded artifacts:
/// a `NotaryService` that trusts `notary` and charges [`NOTARY_FEE_WEI`], and
/// the `GoogleJwtRoots` that verifies through it. Returns them in the order
/// (roots, service).
async fn deploy_stack<P: Provider>(
    provider: &P,
    owner: Address,
    notary: Address,
) -> (Address, Address) {
    let artifacts = Artifacts::embedded();
    let notary_service = deploy_behind_proxy(
        provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: owner,
            notary_: notary,
            fee_: U256::from(NOTARY_FEE_WEI),
        },
        None,
    )
    .await
    .unwrap();
    let jwt_roots = deploy_behind_proxy(
        provider,
        &artifacts,
        "GoogleJwtRoots",
        &GoogleJwtRoots::initializeCall {
            owner_: owner,
            notary_: notary_service,
        },
        None,
    )
    .await
    .unwrap();
    (jwt_roots, notary_service)
}

/// The notary's `createdAt`: bytes 32..40 of the section 9.1 record,
/// big-endian, right after the 32-byte authority id.
fn created_at(attested_data: &[u8]) -> u64 {
    u64::from_be_bytes(attested_data[32..40].try_into().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running notary (KEEPER_E2E_NOTARY) and network to Google"]
async fn keeper_rotates_the_roots_through_a_real_notary() {
    let notary_addr = notary_under_test();
    let trusted = trusted_notary_address();

    // The stack: the one `KEEPER_E2E_GOOGLE_JWT_ROOTS` names, or one deployed
    // here on a chain spawned for this run. `_anvil` holds that chain open.
    let deployed = env_address("KEEPER_E2E_GOOGLE_JWT_ROOTS");
    let (_anvil, rpc_url) = chain_under_test(deployed.is_some());
    let (wallet, deployer) = SignerSource::from_spec(GAS_KEY)
        .unwrap()
        .build_wallet(None)
        .await
        .unwrap();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&rpc_url)
        .await
        .unwrap();

    let (jwt_roots, notary_service) = match deployed {
        Some(jwt_roots) => {
            let service = match env_address("KEEPER_E2E_NOTARY_SERVICE") {
                Some(address) => address,
                None => GoogleJwtRoots::new(jwt_roots, &provider)
                    .notaryService()
                    .call()
                    .await
                    .unwrap(),
            };
            (jwt_roots, service)
        }
        None => deploy_stack(&provider, deployer, trusted).await,
    };

    // No mock: the keeper's cheap poll reads Google's live endpoint, and its
    // proof source is the notary over the wire.
    let dir = tempfile::tempdir().unwrap();
    let path = write_keeper_toml(
        dir.path(),
        &format!(
            "signer = \"{GAS_KEY}\"\n\
             notary_url = \"tcp://{notary_addr}\"\n\
             [[networks]]\n\
             name = \"anvil\"\n\
             rpc_url = \"{rpc_url}\"\n\
             google_jwt_roots = \"{jwt_roots}\"\n"
        ),
    );
    let (config, networks) = KeeperConfig::load(&path).unwrap();

    // The keys the chain must end up trusting: Google's live set, read the
    // same way the keeper's poll reads it. (Google rotating between this
    // fetch and the notarized session would fail the per-key assertions
    // below; that window is seconds wide.)
    let body = reqwest::get(GOOGLE_JWKS_URL)
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let google_keys = decision::parse_google_jwks(&body).unwrap();
    assert!(!google_keys.is_empty(), "Google publishes at least one key");

    // Optionally capture a record first: one extra MPC-TLS session, and the
    // signature is checked to recover to the trusted notary before writing.
    if let Ok(out) = std::env::var("KEEPER_E2E_CAPTURE") {
        let session = ProofSource::from_config(&config)
            .unwrap()
            .obtain()
            .await
            .expect("real notarized session");
        let digest = libid_crypto::keccak256(&session.attested_data);
        let recovered = Address::from(pubkey_to_eth_address(
            &recover_eth_claim(&session.notary_signature, &digest).unwrap(),
        ));
        assert_eq!(
            recovered, trusted,
            "the captured record must be the notary's"
        );
        let record = serde_json::json!({
            "notary": format!("{recovered:#x}"),
            "created_at": created_at(&session.attested_data),
            "attested_data": format!("0x{}", hex::encode(&session.attested_data)),
            "notary_signature": format!("0x{}", hex::encode(&session.notary_signature)),
            "endpoint": GOOGLE_JWKS_URL,
            "captured_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        std::fs::write(&out, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    }

    let roots = GoogleJwtRoots::new(jwt_roots, &provider);
    // Both hold by construction when this test deployed the stack, and are
    // the two ways an EXTERNAL one can be wrong: the fee would land in a
    // service this contract does not verify through, or the notary's
    // signature would recover to a key the service does not trust.
    assert_eq!(
        roots.notaryService().call().await.unwrap(),
        notary_service,
        "the roots contract verifies through another Notary Service"
    );
    assert!(
        NotaryService::new(notary_service, &provider)
            .isTrustedNotary(trusted)
            .call()
            .await
            .unwrap(),
        "the Notary Service does not trust {trusted}, the address the \
         notary's signature recovers to"
    );
    // What one rotation costs, as the chain states it.
    let fee = roots.quoteRotation().call().await.unwrap();
    let service_balance_before = provider.get_balance(notary_service).await.unwrap();

    // ── dry run: rotation needed, nothing submitted, no session ─────────────
    let outcome = run::tick(&config, &networks, true).await;
    assert_eq!(outcome.networks_read, 1);
    assert_eq!(outcome.rotations_needed, 1);
    assert_eq!(outcome.rotations_submitted, 0);
    assert_eq!(outcome.errors, 0);

    // ── the real tick: one MPC-TLS session against Google through the notary,
    // one rotation, one fee ─────────────────────────────────────────────────
    let outcome = run::tick(&config, &networks, false).await;
    assert_eq!(outcome.errors, 0, "the real session or the rotation failed");
    assert_eq!(outcome.rotations_submitted, 1);
    assert!(outcome.is_success());
    for key in &google_keys {
        let expiry = roots
            .trustedHashExpiresAt(key.modulus_hash)
            .call()
            .await
            .unwrap();
        assert!(expiry > U256::ZERO, "modulus of {} not trusted", key.kid);
    }
    let generations = roots.currentKeys().call().await.unwrap();
    assert_eq!(generations.current.moduli.len(), google_keys.len());
    assert!(generations.previous.moduli.is_empty());
    assert!(!roots.needsRotation().call().await.unwrap());
    let service_balance_after = provider.get_balance(notary_service).await.unwrap();
    assert_eq!(service_balance_after - service_balance_before, fee);

    // ── steady state: nothing to do, nothing paid ───────────────────────────
    let outcome = run::tick(&config, &networks, false).await;
    assert_eq!(outcome.rotations_needed, 0);
    assert_eq!(outcome.rotations_submitted, 0);
    assert_eq!(outcome.errors, 0);
    assert_eq!(
        provider.get_balance(notary_service).await.unwrap(),
        service_balance_after
    );
}
