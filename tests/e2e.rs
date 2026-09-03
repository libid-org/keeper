//! Integration tests: config resolution against a real chain-configurations
//! file, and the full keeper loop against a real chain.
//!
//! The end-to-end test is everything but MPC-TLS itself: a real Anvil node,
//! the real `NotaryService` / `GoogleJwtRoots` contracts deployed from
//! libid-contracts' embedded artifacts, a local HTTP server standing in for
//! Google's JWKS endpoint (serving Google's real body), and the notary
//! crate's mock prover (which signs the exact record a real MPC-TLS session
//! produces) as the proof source — wired through keeper.toml, not through
//! test-only APIs, so the config surface is exercised too.

use std::path::Path;

use alloy::{
    node_bindings::Anvil,
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
};
use libid_signer::SignerSource;
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};

/// Anvil's dev key #0 — pays gas and the Notary Fee for deploys and
/// rotations.
const GAS_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Anvil's dev key #1 — the MOCK notary signing key. The `NotaryService` is
/// initialized trusting this key's address, so mock records verify on-chain.
const NOTARY_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
/// The Notary Fee the service is deployed with. Non-zero on purpose: a
/// rotation that forgot to attach it must revert, and the fee must land in
/// the service, not with the roots contract.
const NOTARY_FEE_WEI: u64 = 1_000;

/// Google's real JWKS body (fetched 2026-09-03 with `curl --http1.1`):
/// pretty-printed, two-space indent, LF newlines — the shape the on-chain
/// parser reads in production, so the loop is driven with it rather than
/// with a compact body the keeper would never see.
const GOOGLE_BODY: &str = include_str!("fixtures/certs.json");

/// Write `keeper.toml` (and return its path) inside `dir`.
fn write_keeper_toml(dir: &Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("keeper.toml");
    std::fs::write(&path, contents).expect("write keeper.toml");
    path
}

// ── config resolution ───────────────────────────────────────────────────────

/// A `network_file` reference resolves against the real eden-testnet file
/// (verbatim from chain-configurations). That legacy record has no
/// `[identity]` section — its only JWKS contract was the login stack's
/// `GoogleOidcVerifier`, which is archived — so the file names nothing the
/// keeper serves, and the load says so instead of resolving an empty
/// network.
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

    let err = KeeperConfig::load(&path).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("network 'eden-testnet' names no JWKS contract"),
        "{message}"
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
         google_jwt_roots = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"\n",
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
                 google_jwt_roots = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"\n";
    let path = write_keeper_toml(dir.path(), &format!("{entry}{entry}"));
    let err = KeeperConfig::load(&path).unwrap_err();
    assert!(
        err.to_string().contains("duplicate network name"),
        "{err:#}"
    );
}

// ── the end-to-end loop ─────────────────────────────────────────────────────

/// Serve `body` as an HTTP 200 on a random localhost port; returns the URL —
/// the stand-in for `oauth2/v3/certs`. Both the keeper's poll and the mock
/// prover fetch from here; the mock then frames the body itself, chunked,
/// the way Google does, so what reaches the chain is not this server's
/// framing.
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
/// steady state, asserting the on-chain trust table and the fee along the
/// way.
#[tokio::test(flavor = "multi_thread")]
async fn keeper_rotates_the_roots_then_reaches_steady_state() {
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

    // The on-chain trusted notary IS the mock's signing key — the one
    // configuration under which a mock record verifies.
    let notary_signer = Address::from(pubkey_to_eth_address(
        hex_to_signing_key(NOTARY_KEY).unwrap().verifying_key(),
    ));
    let fee = U256::from(NOTARY_FEE_WEI);

    let artifacts = Artifacts::embedded();
    let notary_service = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: notary_signer,
            fee_: fee,
        },
        None,
    )
    .await
    .unwrap();
    let jwt_roots = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GoogleJwtRoots",
        &GoogleJwtRoots::initializeCall {
            owner_: deployer,
            notary_: notary_service,
        },
        None,
    )
    .await
    .unwrap();

    let jwks_url = serve_jwks(GOOGLE_BODY.to_string()).await;
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
             google_jwt_roots = \"{jwt_roots}\"\n",
            rpc = anvil.endpoint(),
        ),
    );
    let (config, networks) = KeeperConfig::load(&path).unwrap();

    let google_keys = decision::parse_google_jwks(GOOGLE_BODY.as_bytes()).unwrap();
    assert_eq!(google_keys.len(), 2, "Google publishes two keys today");
    let roots = GoogleJwtRoots::new(jwt_roots, &provider);
    assert_eq!(roots.quoteRotation().call().await.unwrap(), fee);
    let service_balance_before = provider.get_balance(notary_service).await.unwrap();

    // ── dry run: the roots need rotation, nothing is submitted ──────────────
    let outcome = run::tick(&config, &networks, true).await;
    assert_eq!(outcome.networks_read, 1);
    assert_eq!(outcome.rotations_needed, 1);
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

    // ── the real tick: one mock session, one rotation, one fee ──────────────
    let outcome = run::tick(&config, &networks, false).await;
    assert_eq!(outcome.networks_read, 1);
    assert_eq!(outcome.rotations_needed, 1);
    assert_eq!(outcome.rotations_submitted, 1);
    assert_eq!(outcome.errors, 0);
    assert!(outcome.is_success());
    for key in &google_keys {
        let expiry = roots
            .trustedHashExpiresAt(key.modulus_hash)
            .call()
            .await
            .unwrap();
        assert!(expiry > U256::ZERO, "modulus of {} not trusted", key.kid);
    }
    // The reading became the current generation, whole: every key Google
    // served, and nothing before it.
    let generations = roots.currentKeys().call().await.unwrap();
    assert_eq!(generations.current.moduli.len(), google_keys.len());
    assert!(generations.previous.moduli.is_empty());
    assert!(!roots.needsRotation().call().await.unwrap());
    // The Notary Fee went to the Notary Service — exactly once, exactly whole.
    let service_balance_after = provider.get_balance(notary_service).await.unwrap();
    assert_eq!(service_balance_after - service_balance_before, fee);

    // ── steady state: a reading lifetime of 30 days is beyond the 7-day
    // threshold, so the next tick reads everything and submits nothing ──────
    let outcome = run::tick(&config, &networks, false).await;
    assert_eq!(outcome.networks_read, 1);
    assert_eq!(outcome.rotations_needed, 0);
    assert_eq!(outcome.rotations_submitted, 0);
    assert_eq!(outcome.errors, 0);
    assert_eq!(
        provider.get_balance(notary_service).await.unwrap(),
        service_balance_after,
        "no rotation, no fee"
    );
}
