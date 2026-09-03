//! `keeper.toml`: schema, parsing, and network resolution.
//!
//! A network is configured either INLINE (`name` + `rpc_url` + contract
//! addresses) or BY REFERENCE to a chain-configurations network file
//! (`network_file = "networks/eden-testnet.toml"`). The referenced file uses
//! the exact TOML schema of the `libid-org/chain-configurations` repo, which
//! is the source of truth for deployed contract addresses — the keeper reads
//! only the fields it needs and ignores the rest, so schema additions over
//! there never break a keeper deployment.

use std::{
    collections::HashSet,
    path::{
        Path,
        PathBuf,
    },
};

use alloy::primitives::Address;
use anyhow::{
    bail,
    Context,
    Result,
};
use serde::Deserialize;

/// Default poll interval: once an hour. Google rotates roughly weekly and
/// the contracts stamp a 30-day TTL, so an hour is comfortably tight.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 60 * 60;

/// Default renewal threshold: rotate when a trusted key expires within seven
/// days. Matches the rotation listener this keeper replaces.
const DEFAULT_RENEWAL_THRESHOLD_SECS: u64 = 7 * 24 * 60 * 60;

/// The parsed `keeper.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperConfig {
    /// TCP address of the libid notary's wire port, `tcp://host:port`
    /// (`host:port` is accepted too). Required to SUBMIT rotations; `status`
    /// and `--dry-run` work without it.
    #[serde(default)]
    pub notary_url: Option<String>,
    /// Seconds between ticks in `run` mode.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Rotate when a trusted key's on-chain expiry is within this many
    /// seconds.
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold_secs: u64,
    /// Default gas signer spec for every network: a 64-char hex private key
    /// (with or without `0x`) or an AWS KMS id/alias/ARN. Classified by
    /// shape via `libid_signer::SignerSource::from_spec`.
    #[serde(default)]
    pub signer: Option<String>,
    /// TEST-ONLY seam: skip MPC-TLS and build notarized sessions with
    /// [`notary::jwks::mock::MockProver`] signing with this key. The chain
    /// accepts them only where this key IS a notary the Notary Service
    /// trusts, which is never true of a production deployment. Refused
    /// alongside `notary_url`.
    #[serde(default)]
    pub mock_notary: Option<MockNotary>,
    /// The networks to keep fresh.
    #[serde(default)]
    pub networks: Vec<NetworkEntry>,
}

fn default_poll_interval() -> u64 {
    DEFAULT_POLL_INTERVAL_SECS
}

fn default_renewal_threshold() -> u64 {
    DEFAULT_RENEWAL_THRESHOLD_SECS
}

/// `[mock_notary]` — the test seam. See [`KeeperConfig::mock_notary`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockNotary {
    /// Hex secp256k1 key the mock proof is signed with.
    pub signing_key: String,
    /// Override the JWKS URL the mock prover fetches (defaults to Google's
    /// live endpoint; tests point it at a local fixture server).
    #[serde(default)]
    pub jwks_url: Option<String>,
}

/// One `[[networks]]` entry, before resolution. Either inline or by
/// reference — the two shapes share optional fields, so resolution (not
/// serde) enforces the split and produces readable errors.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEntry {
    /// Inline: network name (used in logs and the status table).
    #[serde(default)]
    pub name: Option<String>,
    /// Inline: JSON-RPC endpoint.
    #[serde(default)]
    pub rpc_url: Option<String>,
    /// Inline: address of the `IdentityJwksRoots` proxy.
    #[serde(default)]
    pub identity_jwks_roots: Option<String>,
    /// By reference: path to a chain-configurations network file, relative
    /// to the keeper.toml that names it. Mutually exclusive with the inline
    /// fields above — the file is the source of truth.
    #[serde(default)]
    pub network_file: Option<PathBuf>,
    /// Per-network gas signer spec, overriding the global `signer`.
    #[serde(default)]
    pub signer: Option<String>,
}

/// A network after resolution: the contract known, its address parsed.
///
/// One JWKS contract per network: `IdentityJwksRoots`, the naming system's
/// Google trust list, which verifies a rotation through the Notary Service.
/// The login stack's `GoogleOidcVerifier` used to be a second target; it is
/// archived with the rest of that product and is not kept fresh any more.
#[derive(Debug, Clone)]
pub struct ResolvedNetwork {
    /// Network name.
    pub name: String,
    /// JSON-RPC endpoint.
    pub rpc_url: String,
    /// Gas signer spec (per-network override, else the global default).
    pub signer: Option<String>,
    /// The `IdentityJwksRoots` proxy on this network.
    pub identity_jwks_roots: Address,
}

impl KeeperConfig {
    /// Load and validate a keeper.toml. `path`'s parent directory anchors
    /// relative `network_file` references.
    pub fn load(path: &Path) -> Result<(Self, Vec<ResolvedNetwork>)> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let networks = config.resolve_networks(base)?;
        Ok((config, networks))
    }

    /// Resolve every `[[networks]]` entry against `base` (the directory the
    /// keeper.toml lives in).
    pub fn resolve_networks(&self, base: &Path) -> Result<Vec<ResolvedNetwork>> {
        if self.notary_url.is_some() && self.mock_notary.is_some() {
            bail!(
                "both notary_url and [mock_notary] are set — the mock is a test \
                 seam, not a fallback; configure exactly one proof source"
            );
        }
        if self.networks.is_empty() {
            bail!("no [[networks]] configured");
        }
        let mut out = Vec::with_capacity(self.networks.len());
        let mut seen = HashSet::new();
        for entry in &self.networks {
            let resolved = entry.resolve(base, self.signer.as_deref())?;
            if !seen.insert(resolved.name.clone()) {
                bail!("duplicate network name '{}'", resolved.name);
            }
            out.push(resolved);
        }
        Ok(out)
    }
}

impl NetworkEntry {
    fn resolve(
        &self,
        base: &Path,
        global_signer: Option<&str>,
    ) -> Result<ResolvedNetwork> {
        let signer = self
            .signer
            .clone()
            .or_else(|| global_signer.map(str::to_string));
        let resolved = match &self.network_file {
            Some(file) => {
                if self.name.is_some()
                    || self.rpc_url.is_some()
                    || self.identity_jwks_roots.is_some()
                {
                    bail!(
                        "network entry referencing '{}' also sets inline fields — \
                         the chain-configurations file is the source of truth; \
                         only `signer` may accompany `network_file`",
                        file.display()
                    );
                }
                let path = if file.is_absolute() {
                    file.clone()
                } else {
                    base.join(file)
                };
                let parsed = NetworkFile::load(&path)?;
                (
                    parsed.network.name,
                    parsed.network.rpc_url,
                    parsed.identity_jwks_roots,
                )
            }
            None => {
                let name = self
                    .name
                    .clone()
                    .context("inline network entry is missing `name`")?;
                let rpc_url = self.rpc_url.clone().with_context(|| {
                    format!("inline network '{name}' is missing `rpc_url`")
                })?;
                let roots = parse_roots(self.identity_jwks_roots.as_deref(), &name)?;
                (name, rpc_url, roots)
            }
        };
        let (name, rpc_url, roots) = resolved;
        let Some(identity_jwks_roots) = roots else {
            bail!(
                "network '{name}' names no JWKS contract (set identity_jwks_roots, \
                 or reference a network file with it deployed)"
            );
        };
        Ok(ResolvedNetwork {
            name,
            rpc_url,
            signer,
            identity_jwks_roots,
        })
    }
}

/// Parse the `identity_jwks_roots` address, which may be absent or empty
/// ("" means "not deployed" in the chain-configurations convention).
fn parse_roots(value: Option<&str>, network: &str) -> Result<Option<Address>> {
    let Some(raw) = value else { return Ok(None) };
    if raw.is_empty() {
        return Ok(None);
    }
    let address = raw.parse().with_context(|| {
        format!("network '{network}': invalid identity_jwks_roots address '{raw}'")
    })?;
    Ok(Some(address))
}

// ── chain-configurations network files ──────────────────────────────────────
// A LENIENT mirror of the schema in libid-org/chain-configurations (see
// bin/libid-deploy/src/config.rs there): only the fields the keeper consumes
// are declared and unknown fields are ignored, so that repo can evolve its
// schema without breaking keepers. That repo remains the source of truth for
// what is deployed where.

/// The subset of a chain-configurations network file the keeper reads.
#[derive(Debug, Clone, Deserialize)]
struct NetworkFile {
    network: NetworkFileNetwork,
    #[serde(default)]
    identity: Option<NetworkFileIdentity>,
}

/// `[network]`.
#[derive(Debug, Clone, Deserialize)]
struct NetworkFileNetwork {
    name: String,
    rpc_url: String,
}

/// `[identity]` — absent section = identity stack not wanted.
#[derive(Debug, Clone, Deserialize)]
struct NetworkFileIdentity {
    #[serde(default)]
    identity_jwks_roots: Option<String>,
}

/// A network file plus the address extracted from it (`None` when the file
/// records no deployed `IdentityJwksRoots`).
struct ParsedNetworkFile {
    network: NetworkFileNetwork,
    identity_jwks_roots: Option<Address>,
}

impl NetworkFile {
    fn load(path: &Path) -> Result<ParsedNetworkFile> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading network file {}", path.display()))?;
        let parsed: Self = toml::from_str(&text)
            .with_context(|| format!("parsing network file {}", path.display()))?;
        let identity_jwks_roots = parse_roots(
            parsed
                .identity
                .as_ref()
                .and_then(|i| i.identity_jwks_roots.as_deref()),
            &parsed.network.name,
        )?;
        Ok(ParsedNetworkFile {
            network: parsed.network,
            identity_jwks_roots,
        })
    }
}
