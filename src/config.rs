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
    /// TEST-ONLY seam: skip MPC-TLS and build proofs with
    /// [`notary::jwks::mock::MockProver`] signing with this key. The chain
    /// accepts them only where this key IS the on-chain notary signer, which
    /// is never true of a production deployment. Refused alongside
    /// `notary_url`.
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
    /// Inline: address of the `GoogleOidcVerifier` proxy.
    #[serde(default)]
    pub google_oidc_verifier: Option<String>,
    /// By reference: path to a chain-configurations network file, relative
    /// to the keeper.toml that names it. Mutually exclusive with the inline
    /// fields above — the file is the source of truth.
    #[serde(default)]
    pub network_file: Option<PathBuf>,
    /// Per-network gas signer spec, overriding the global `signer`.
    #[serde(default)]
    pub signer: Option<String>,
}

/// Which JWKS contract a rotation targets. Both expose the same
/// `rotate(NotarizedJwksProof, JwkClaim[])` ABI; they differ in how trust is
/// read back (see [`crate::chain`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    /// The identity-names stack's Google JWKS trust list.
    IdentityJwksRoots,
    /// The login stack's Google OIDC verifier.
    GoogleOidcVerifier,
}

impl ContractKind {
    /// Stable label for logs and the status table.
    pub fn label(&self) -> &'static str {
        match self {
            Self::IdentityJwksRoots => "identity_jwks_roots",
            Self::GoogleOidcVerifier => "google_oidc_verifier",
        }
    }
}

/// One contract to keep fresh.
#[derive(Debug, Clone)]
pub struct Target {
    /// Which contract shape lives at the address.
    pub kind: ContractKind,
    /// The proxy address.
    pub address: Address,
}

/// A network after resolution: every target known, every address parsed.
#[derive(Debug, Clone)]
pub struct ResolvedNetwork {
    /// Network name.
    pub name: String,
    /// JSON-RPC endpoint.
    pub rpc_url: String,
    /// Gas signer spec (per-network override, else the global default).
    pub signer: Option<String>,
    /// The JWKS contracts on this network.
    pub targets: Vec<Target>,
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
                    || self.google_oidc_verifier.is_some()
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
                ResolvedNetwork {
                    name: parsed.network.name,
                    rpc_url: parsed.network.rpc_url,
                    signer,
                    targets: parsed.targets,
                }
            }
            None => {
                let name = self
                    .name
                    .clone()
                    .context("inline network entry is missing `name`")?;
                let rpc_url = self.rpc_url.clone().with_context(|| {
                    format!("inline network '{name}' is missing `rpc_url`")
                })?;
                let mut targets = Vec::new();
                push_target(
                    &mut targets,
                    ContractKind::IdentityJwksRoots,
                    self.identity_jwks_roots.as_deref(),
                    &name,
                )?;
                push_target(
                    &mut targets,
                    ContractKind::GoogleOidcVerifier,
                    self.google_oidc_verifier.as_deref(),
                    &name,
                )?;
                ResolvedNetwork {
                    name,
                    rpc_url,
                    signer,
                    targets,
                }
            }
        };
        if resolved.targets.is_empty() {
            bail!(
                "network '{}' names no JWKS contract (set identity_jwks_roots \
                 and/or google_oidc_verifier, or reference a network file with \
                 them deployed)",
                resolved.name
            );
        }
        Ok(resolved)
    }
}

/// Parse an address that may be absent or empty ("" means "not deployed" in
/// the chain-configurations convention) and push a target when present.
fn push_target(
    targets: &mut Vec<Target>,
    kind: ContractKind,
    value: Option<&str>,
    network: &str,
) -> Result<()> {
    let Some(raw) = value else { return Ok(()) };
    if raw.is_empty() {
        return Ok(());
    }
    let address: Address = raw.parse().with_context(|| {
        format!(
            "network '{network}': invalid {} address '{raw}'",
            kind.label()
        )
    })?;
    targets.push(Target { kind, address });
    Ok(())
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
    contracts: NetworkFileContracts,
    #[serde(default)]
    identity: Option<NetworkFileIdentity>,
}

/// `[network]`.
#[derive(Debug, Clone, Deserialize)]
struct NetworkFileNetwork {
    name: String,
    rpc_url: String,
}

/// `[contracts]` — OUTPUT keys over there; empty string = not deployed.
#[derive(Debug, Clone, Default, Deserialize)]
struct NetworkFileContracts {
    #[serde(default)]
    google_oidc_verifier: String,
}

/// `[identity]` — absent section = identity stack not wanted.
#[derive(Debug, Clone, Deserialize)]
struct NetworkFileIdentity {
    #[serde(default)]
    identity_jwks_roots: Option<String>,
}

/// A network file plus the targets extracted from it.
struct ParsedNetworkFile {
    network: NetworkFileNetwork,
    targets: Vec<Target>,
}

impl NetworkFile {
    fn load(path: &Path) -> Result<ParsedNetworkFile> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading network file {}", path.display()))?;
        let parsed: Self = toml::from_str(&text)
            .with_context(|| format!("parsing network file {}", path.display()))?;
        let mut targets = Vec::new();
        push_target(
            &mut targets,
            ContractKind::IdentityJwksRoots,
            parsed
                .identity
                .as_ref()
                .and_then(|i| i.identity_jwks_roots.as_deref()),
            &parsed.network.name,
        )?;
        push_target(
            &mut targets,
            ContractKind::GoogleOidcVerifier,
            Some(parsed.contracts.google_oidc_verifier.as_str()),
            &parsed.network.name,
        )?;
        Ok(ParsedNetworkFile {
            network: parsed.network,
            targets,
        })
    }
}
