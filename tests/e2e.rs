//! Integration tests: config resolution against a real chain-configurations
//! file, and the full keeper loop against a real chain.
//!
//! The end-to-end test is everything but MPC-TLS itself: a real Anvil node,
//! the real `Notary` / `IdentityJwksRoots` / `GoogleOidcVerifier` contracts
//! deployed from libid-contracts' embedded artifacts, a local HTTP server
//! standing in for Google's JWKS endpoint, and the notary crate's mock prover
//! (which signs the exact digest a real MPC-TLS session produces) as the
//! proof source — wired through keeper.toml, not through test-only APIs, so
//! the config surface is exercised too.

use std::path::Path;

use alloy::{
    node_bindings::Anvil,
    primitives::{
        Address,
        U256,
    },
    providers::ProviderBuilder,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use keeper::{
    config::{
        ContractKind,
        KeeperConfig,
    },
    decision,
    run,
};
use libid_contracts::{
    artifacts::Artifacts,
    bindings::{
        identity::IdentityJwksRoots,
        notary::Notary,
        oidc::GoogleOidcVerifier,
    },
    deploy::deploy_behind_proxy,
};
use libid_crypto::{
    hex_to_signing_key,
    pubkey_to_eth_address,
};
use libid_signer::SignerSource;
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};

/// Anvil's dev key #0 — pays gas for deploys and rotations.
const GAS_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Anvil's dev key #1 — the MOCK notary signing key. The `Notary` contract is
/// initialized with this key's address, so mock proofs verify on-chain.
const NOTARY_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Write `keeper.toml` (and return its path) inside `dir`.
fn write_keeper_toml(dir: &Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("keeper.toml");
    std::fs::write(&path, contents).expect("write keeper.toml");
    path
}

// ── config resolution ───────────────────────────────────────────────────────

/// A `network_file` reference resolves against the real eden-testnet file
/// (verbatim from chain-configurations): the RPC and the deployed
/// `google_oidc_verifier` come out, and the absent `[identity]` section
/// yields no `identity_jwks_roots` target.
#[test]
fn network_file_reference_resolves_the_chain_configurations_schema() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/eden-testnet.toml"
    );
    let path = write_keeper_toml(
        dir.path(),
        &format!("[[networks]]\nnetwork_file = \"{fixture}\"\n"),
    );

    let (_, networks) = KeeperConfig::load(&path).unwrap();
    assert_eq!(networks.len(), 1);
    let network = &networks[0];
    assert_eq!(network.name, "eden-testnet");
    assert_eq!(
        network.rpc_url,
        "https://ev-reth-eden-testnet.binarybuilders.services:8545"
    );
    assert_eq!(network.targets.len(), 1);
    assert_eq!(network.targets[0].kind, ContractKind::GoogleOidcVerifier);
    assert_eq!(
        network.targets[0].address,
        "0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e"
            .parse::<Address>()
            .unwrap()
    );
}

/// The mock is a test seam, not a fallback: configuring it alongside a real
/// notary is refused at load.
#[test]
fn config_refuses_notary_url_alongside_mock_notary() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "notary_url = \"tcp://127.0.0.1:7047\"\n\
         [mock_notary]\n\
         signing_key = \"ab\"\n\
         [[networks]]\n\
         name = \"n\"\n\
         rpc_url = \"http://127.0.0.1:1\"\n\
         identity_jwks_roots = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"\n",
    );
    let err = KeeperConfig::load(&path).unwrap_err();
    assert!(err.to_string().contains("test seam"), "{err:#}");
}

/// Two entries resolving to the same name would double-submit; refused.
#[test]
fn config_refuses_duplicate_network_names() {
    let dir = tempfile::tempdir().unwrap();
    let entry = "[[networks]]\n\
                 name = \"n\"\n\
                 rpc_url = \"http://127.0.0.1:1\"\n\
                 identity_jwks_roots = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"\n";
    let path = write_keeper_toml(dir.path(), &format!("{entry}{entry}"));
    let err = KeeperConfig::load(&path).unwrap_err();
    assert!(
        err.to_string().contains("duplicate network name"),
        "{err:#}"
    );
}

// ── the end-to-end loop ─────────────────────────────────────────────────────

/// A deterministic 256-byte RSA modulus (the contracts reject any other
/// length), base64url-encoded the way Google publishes `n`.
fn test_modulus(seed: u8) -> String {
    let bytes: Vec<u8> = (0..256u16)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) | 0x01)
        .collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The JWKS body both the keeper's poll and the mock prover read.
fn jwks_fixture_body() -> String {
    serde_json::json!({
        "keys": [
            {"kty": "RSA", "alg": "RS256", "use": "sig",
             "kid": "e2e-key-1", "n": test_modulus(3), "e": "AQAB"},
            {"kty": "RSA", "alg": "RS256", "use": "sig",
             "kid": "e2e-key-2", "n": test_modulus(89), "e": "AQAB"},
        ]
    })
    .to_string()
}

/// Serve `body` as an HTTP 200 on a random localhost port; returns the URL —
/// the stand-in for `oauth2/v3/certs`.
async fn serve_jwks(body: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture server");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://{addr}/oauth2/v3/certs")
}

/// The whole loop against a real chain: deploy the real contracts, point the
/// keeper at a JWKS fixture, and drive `tick` through dry-run → rotation →
/// steady state, asserting the on-chain trust tables along the way.
#[tokio::test(flavor = "multi_thread")]
async fn keeper_rotates_both_contracts_then_reaches_steady_state() {
    let anvil = Anvil::new().spawn();
    let (wallet, deployer) = SignerSource::from_spec(GAS_KEY)
        .unwrap()
        .build_wallet(None)
        .await
        .unwrap();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&anvil.endpoint())
        .await
        .unwrap();

    // The on-chain notary signer IS the mock's signing key — the one
    // configuration under which a mock proof verifies.
    let notary_signer = Address::from(pubkey_to_eth_address(
        hex_to_signing_key(NOTARY_KEY).unwrap().verifying_key(),
    ));

    let artifacts = Artifacts::embedded();
    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "Notary",
        &Notary::initializeCall {
            owner_: deployer,
            notary_: notary_signer,
        },
        None,
    )
    .await
    .unwrap();
    let jwks_roots = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityJwksRoots",
        &IdentityJwksRoots::initializeCall {
            owner_: deployer,
            notaryContract_: notary_proxy,
        },
        None,
    )
    .await
    .unwrap();
    let oidc_verifier = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GoogleOidcVerifier",
        &GoogleOidcVerifier::initializeCall {
            // rotate() never touches the Honk verifier; any nonzero address
            // satisfies initialize.
            _verifier: Address::repeat_byte(0x42),
            _owner: deployer,
            notaryContract_: notary_proxy,
            initialAud: "e2e-client-id".into(),
        },
        None,
    )
    .await
    .unwrap();

    let jwks_url = serve_jwks(jwks_fixture_body()).await;
    let dir = tempfile::tempdir().unwrap();
    let path = write_keeper_toml(
        dir.path(),
        &format!(
            "signer = \"{GAS_KEY}\"\n\
             [mock_notary]\n\
             signing_key = \"{NOTARY_KEY}\"\n\
             jwks_url = \"{jwks_url}\"\n\
             [[networks]]\n\
             name = \"anvil\"\n\
             rpc_url = \"{rpc}\"\n\
             identity_jwks_roots = \"{jwks_roots}\"\n\
             google_oidc_verifier = \"{oidc_verifier}\"\n",
            rpc = anvil.endpoint(),
        ),
    );
    let (config, networks) = KeeperConfig::load(&path).unwrap();

    let google_keys =
        decision::parse_google_jwks(jwks_fixture_body().as_bytes()).unwrap();
    let roots = IdentityJwksRoots::new(jwks_roots, &provider);
    let verifier = GoogleOidcVerifier::new(oidc_verifier, &provider);

    // ── dry run: both contracts need rotation, nothing is submitted ─────────
    let outcome = run::tick(&config, &networks, true).await;
    assert_eq!(outcome.targets_read, 2);
    assert_eq!(outcome.rotations_needed, 2);
    assert_eq!(outcome.rotations_submitted, 0);
    assert_eq!(outcome.errors, 0);
    for key in &google_keys {
        let expiry = roots
            .trustedHashExpiresAt(key.modulus_hash)
            .call()
            .await
            .unwrap();
        assert_eq!(expiry, U256::ZERO, "dry run must not touch the chain");
    }

    // ── the real tick: one mock proof serves both contracts ─────────────────
    let outcome = run::tick(&config, &networks, false).await;
    assert_eq!(outcome.targets_read, 2);
    assert_eq!(outcome.rotations_needed, 2);
    assert_eq!(outcome.rotations_submitted, 2);
    assert_eq!(outcome.errors, 0);
    assert!(outcome.is_success());
    for key in &google_keys {
        let expiry = roots
            .trustedHashExpiresAt(key.modulus_hash)
            .call()
            .await
            .unwrap();
        assert!(expiry > U256::ZERO, "modulus of {} not trusted", key.kid);
        let modulus = verifier.modulusOfKid(key.kid_hash).call().await.unwrap();
        assert_eq!(
            modulus, key.modulus_hash,
            "kid {} modulus mismatch",
            key.kid
        );
        let expiry = verifier.expiresAtKid(key.kid_hash).call().await.unwrap();
        assert!(expiry > U256::ZERO, "kid {} not stamped", key.kid);
    }

    // ── steady state: freshly stamped 30-day TTLs are beyond the 7-day
    // threshold, so the next tick reads everything and submits nothing ──────
    let outcome = run::tick(&config, &networks, false).await;
    assert_eq!(outcome.targets_read, 2);
    assert_eq!(outcome.rotations_needed, 0);
    assert_eq!(outcome.rotations_submitted, 0);
    assert_eq!(outcome.errors, 0);
}
