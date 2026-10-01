//! Integration tests: config resolution against a real chain-configurations
//! file, the strictness a `keeper.toml` is held to, and where a referenced
//! network's endpoint comes from.

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

/// `keeper.toml` is strict: a key the schema does not declare fails the load
/// by name, so a typo, or a key a release removed, cannot ride along silently
/// and be read as "unset".
#[test]
fn config_refuses_a_key_it_does_not_declare() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "[proof]\n\
         signing_key = \"ab\"\n\
         [[networks]]\n\
         name = \"n\"\n\
         rpc_url = \"http://127.0.0.1:1\"\n\
         google_jwt_roots = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"\n",
    );
    let err = KeeperConfig::load(&path).unwrap_err();
    let message = format!("{err:#}");
    assert!(message.contains("unknown field `proof`"), "{message}");
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

// ── the endpoint of a referenced network ────────────────────────────────────

/// A real network's file as chain-configurations ships it: no `rpc_url`.
const SEPOLIA: &str = "[network]\n\
                       name = \"sepolia\"\n\
                       chain_id = 11155111\n\
                       [contracts]\n\
                       google_jwt_roots = \"0xb7a2ce28e71dbb9c877d2b5a48de33b5f0e6838d\"\n";

/// local-dev's file, which names the compose service its stack reaches.
const LOCAL_DEV: &str = "[network]\n\
                         name = \"local-dev\"\n\
                         chain_id = 31337\n\
                         rpc_url = \"http://anvil:8545\"\n\
                         [contracts]\n\
                         google_jwt_roots = \"0xb7a2ce28e71dbb9c877d2b5a48de33b5f0e6838d\"\n";

/// A real network's endpoint is a secret of the environment that reaches it,
/// so its file names none: the entry's `rpc_url` supplies it, and the file
/// still names the network.
#[test]
fn network_file_without_an_endpoint_takes_the_entrys_rpc_url() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sepolia.toml"), SEPOLIA).unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "[[networks]]\n\
         network_file = \"sepolia.toml\"\n\
         rpc_url = \"https://sepolia.example/v2/key\"\n",
    );

    let (_, networks) = KeeperConfig::load(&path).unwrap();
    let [network] = networks.as_slice() else {
        panic!("one entry resolves to one network, got {networks:?}");
    };
    assert_eq!(network.name, "sepolia");
    assert_eq!(network.rpc_url, "https://sepolia.example/v2/key");
}

/// Neither the file nor the entry names an endpoint: the load fails, and the
/// message names the file that lacks one and the key to set beside it.
#[test]
fn network_file_without_an_endpoint_needs_the_entrys_rpc_url() {
    let dir = tempfile::tempdir().unwrap();
    let network_file = dir.path().join("sepolia.toml");
    std::fs::write(&network_file, SEPOLIA).unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "[[networks]]\nnetwork_file = \"sepolia.toml\"\n",
    );

    let err = KeeperConfig::load(&path).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains(&format!("{} names no `rpc_url`", network_file.display())),
        "{message}"
    );
    assert!(
        message.contains("set `rpc_url` beside `network_file`"),
        "{message}"
    );
}

/// chain-configurations reads an empty `rpc_url` as none, so a file that
/// spells it that way is refused like one without the key, never resolved to
/// an empty endpoint.
#[test]
fn network_file_with_an_empty_rpc_url_names_no_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mainnet.toml"),
        "[network]\n\
         name = \"mainnet\"\n\
         rpc_url = \"\"\n\
         [contracts]\n\
         google_jwt_roots = \"0xb7a2ce28e71dbb9c877d2b5a48de33b5f0e6838d\"\n",
    )
    .unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "[[networks]]\nnetwork_file = \"mainnet.toml\"\n",
    );

    let err = KeeperConfig::load(&path).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("network 'mainnet' has no endpoint"),
        "{message}"
    );
}

/// A file that names its endpoint serves an entry that sets none.
#[test]
fn network_file_endpoint_serves_an_entry_that_sets_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("local-dev.toml"), LOCAL_DEV).unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "[[networks]]\nnetwork_file = \"local-dev.toml\"\n",
    );

    let (_, networks) = KeeperConfig::load(&path).unwrap();
    let [network] = networks.as_slice() else {
        panic!("one entry resolves to one network, got {networks:?}");
    };
    assert_eq!(network.name, "local-dev");
    assert_eq!(network.rpc_url, "http://anvil:8545");
}

/// Where the file names an endpoint, the entry's `rpc_url` wins: local-dev's
/// compose service name resolves only inside its network, and a keeper on the
/// host reaches the same chain at the published port.
#[test]
fn entry_rpc_url_wins_over_the_network_files_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("local-dev.toml"), LOCAL_DEV).unwrap();
    let path = write_keeper_toml(
        dir.path(),
        "[[networks]]\n\
         network_file = \"local-dev.toml\"\n\
         rpc_url = \"http://127.0.0.1:8545\"\n",
    );

    let (_, networks) = KeeperConfig::load(&path).unwrap();
    let [network] = networks.as_slice() else {
        panic!("one entry resolves to one network, got {networks:?}");
    };
    assert_eq!(network.name, "local-dev");
    assert_eq!(network.rpc_url, "http://127.0.0.1:8545");
}

/// The file stays the source of truth for the network's name and its
/// contract: an entry that states either beside `network_file` is refused.
#[test]
fn network_file_entry_refuses_name_and_google_jwt_roots() {
    let fields = [
        "name = \"other\"",
        "google_jwt_roots = \"0x69cc7c69b39ada71ce908d432868d5ef9a6a6d0e\"",
    ];

    for field in fields {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("local-dev.toml"), LOCAL_DEV).unwrap();
        let path = write_keeper_toml(
            dir.path(),
            &format!("[[networks]]\nnetwork_file = \"local-dev.toml\"\n{field}\n"),
        );

        let err = KeeperConfig::load(&path).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("only `rpc_url` and `signer` may accompany `network_file`"),
            "{field}: {message}"
        );
    }
}
