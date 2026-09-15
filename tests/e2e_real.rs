//! The whole loop for real: a running notary, the contract stack
//! `libid-deploy` lays down on anvil, Google's live JWKS, and one genuine
//! MPC-TLS rotation.
//!
//! The only test that drives a rotation: the keeper's prover runs a real
//! session against `www.googleapis.com` through a notary it does not share a
//! crate with, reads the signed record back off the wire, and
//! `GoogleJwtRoots` accepts it. It is `#[ignore]`d because it needs two
//! things a plain `cargo test` does not have -- the stack in `compose.yaml`
//! and network to Google -- so CI runs it in a job of its own.
//!
//! # Running it
//!
//! ```sh
//! echo "127.0.0.1 anvil" | sudo tee -a /etc/hosts   # once per machine
//! docker compose up -d --wait --build
//! cargo test --test e2e_real -- --ignored --nocapture
//! docker compose down                                # a fresh chain per run
//! ```
//!
//! # The stack under test
//!
//! `e2e/local-dev.toml` is chain-configurations' published network file,
//! byte for byte (the compose build proves it). The keeper reads it the way a
//! deployment's `keeper.toml` does, through `network_file`: the chain, and
//! the `GoogleJwtRoots` address, are whatever the keeper's own parser
//! resolves from it, and everything this test drives comes from that
//! resolution. Nothing here extracts an address by other means. The file
//! names the chain by its compose service name, hence the hosts line above.
//!
//! * `KEEPER_E2E_NETWORK_FILE=<path>` -- drive another network file. Its
//!   stack must be fresh (the test asserts a FIRST rotation), its Notary
//!   Service must trust the key the notary signs with, and Anvil's dev key
//!   #0 must be funded on its chain, since that key pays gas and the fee.
//! * `KEEPER_E2E_NOTARY=host:port` -- another notary. Defaults to
//!   `127.0.0.1:7047`, where compose publishes the stack's.
//! * `KEEPER_E2E_NOTARY_ADDRESS=0x…` -- the trusted notary address, when the
//!   notary signs with a key other than Anvil's dev key #1.
//! * `KEEPER_E2E_CAPTURE=<path>` -- also write the record the keeper
//!   obtained -- attested data, signature, the address the signature
//!   recovers to and the notary's `createdAt` -- as JSON, which is how a
//!   contract test gets a fixture Google actually served.

use std::path::{
    Path,
    PathBuf,
};

use alloy::{
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
use libid_contracts::bindings::ceremony::{
    GoogleJwtRoots,
    NotaryService,
};
use libid_crypto::{
    hex_to_signing_key,
    pubkey_to_eth_address,
    recover_eth_claim,
};
use libid_signer::SignerSource;
use serde::Deserialize;

/// Anvil's dev key #0 -- pays gas and the Notary Fee.
const GAS_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Anvil's dev key #1 -- the key the notary under test is expected to sign
/// with, so the deployed `NotaryService` trusts it.
const NOTARY_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// Where compose publishes the stack's notary.
const DEFAULT_NOTARY: &str = "127.0.0.1:7047";
/// Google's live key set -- the same endpoint the notarized session reads.
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

fn write_keeper_toml(dir: &Path, contents: &str) -> PathBuf {
    let path = dir.join("keeper.toml");
    std::fs::write(&path, contents).unwrap();
    path
}

/// The network file this run drives: `KEEPER_E2E_NETWORK_FILE`, or the
/// published local-dev file the compose stack is deployed from.
fn network_file_under_test() -> PathBuf {
    std::env::var_os("KEEPER_E2E_NETWORK_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("e2e/local-dev.toml")
        })
}

/// The notary this run talks to, from `KEEPER_E2E_NOTARY`, else the stack's.
fn notary_under_test() -> String {
    std::env::var("KEEPER_E2E_NOTARY").unwrap_or_else(|_| DEFAULT_NOTARY.to_string())
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

/// What the network file declares and the keeper does not read: the Notary
/// Service the roots contract must verify through, and the fee land in.
/// Read here only to hold the deployed stack to its own declaration.
#[derive(Deserialize)]
struct DeclaredStack {
    contracts: DeclaredContracts,
}

#[derive(Deserialize)]
struct DeclaredContracts {
    notary_service: Address,
}

/// The notary's `createdAt`: bytes 32..40 of the section 9.1 record,
/// big-endian, right after the 32-byte authority id.
fn created_at(attested_data: &[u8]) -> u64 {
    u64::from_be_bytes(attested_data[32..40].try_into().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the compose stack (docker compose up -d --wait) and network to Google"]
async fn keeper_rotates_the_roots_through_a_real_notary() {
    let notary_addr = notary_under_test();
    let trusted = trusted_notary_address();
    let network_file = network_file_under_test();

    // The keeper's view of the stack: the network file, by reference, the
    // way a deployment's keeper.toml names it. The keeper's cheap poll reads
    // Google's live endpoint, and its proof source is the notary over the
    // wire. The resolved network -- its chain and its roots contract -- is
    // what the rest of this test drives, so the parser is under test, not
    // bypassed.
    let dir = tempfile::tempdir().unwrap();
    let path = write_keeper_toml(
        dir.path(),
        &format!(
            "signer = \"{GAS_KEY}\"\n\
             notary_url = \"tcp://{notary_addr}\"\n\
             [[networks]]\n\
             network_file = \"{}\"\n",
            network_file.display()
        ),
    );
    let (config, networks) = KeeperConfig::load(&path).unwrap();
    let [network] = networks.as_slice() else {
        panic!("one network file resolves to one network, got {networks:?}");
    };
    let jwt_roots = network.google_jwt_roots;
    let declared: DeclaredStack =
        toml::from_str(&std::fs::read_to_string(&network_file).unwrap()).unwrap();
    let notary_service = declared.contracts.notary_service;

    let (wallet, _) = SignerSource::from_spec(GAS_KEY)
        .unwrap()
        .build_wallet(None)
        .await
        .unwrap();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&network.rpc_url)
        .await
        .unwrap();

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
    // The two ways a deployed stack can be wrong for this keeper: the fee
    // would land in a service the roots contract does not verify through,
    // or the notary's signature would recover to a key the service does not
    // trust.
    assert_eq!(
        roots.notaryService().call().await.unwrap(),
        notary_service,
        "the roots contract verifies through a Notary Service other than the \
         one the network file declares"
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
