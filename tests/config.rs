//! Integration tests: config resolution against a real chain-configurations
//! file, and the strictness a `keeper.toml` is held to.

use std::path::Path;

use keeper::config::KeeperConfig;

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

/// chain-configurations 0.10 renamed the field and moved its section:
/// `[identity].identity_jwks_roots` became `[contracts].google_jwt_roots`,
/// and `[identity]` went away. A keeper has to serve files from both eras,
/// so both spellings resolve to the same address.
#[test]
fn network_file_reads_both_spellings_of_the_roots_address() {
    const ADDRESS: &str = "0xb7a2ce28e71dbb9c877d2b5a48de33b5f0e6838d";
    let cases = [
        (
            "contracts",
            format!("[contracts]\ngoogle_jwt_roots = \"{ADDRESS}\"\n"),
        ),
        (
            "identity",
            format!("[identity]\nidentity_jwks_roots = \"{ADDRESS}\"\n"),
        ),
    ];

    for (era, section) in cases {
        let dir = tempfile::tempdir().unwrap();
        let network_file = dir.path().join("local-dev.toml");
        std::fs::write(
            &network_file,
            format!(
                "[network]\nname = \"local-dev\"\nrpc_url = \"http://127.0.0.1:8545\"\n\n{section}"
            ),
        )
        .unwrap();
        let path = write_keeper_toml(
            dir.path(),
            &format!(
                "[[networks]]\nnetwork_file = \"{}\"\n",
                network_file.display()
            ),
        );

        let (_, networks) = KeeperConfig::load(&path)
            .unwrap_or_else(|e| panic!("{era} era should resolve: {e:#}"));
        assert_eq!(networks.len(), 1, "{era}");
        assert_eq!(networks[0].name, "local-dev", "{era}");
        assert_eq!(
            networks[0].google_jwt_roots,
            ADDRESS.parse::<alloy::primitives::Address>().unwrap(),
            "{era}"
        );
    }
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
