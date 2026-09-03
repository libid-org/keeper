//! The tick: poll → decide → (maybe) notarize → submit. Plus the read-only
//! status table.

use alloy::providers::ProviderBuilder;
use anyhow::{
    bail,
    Context,
    Result,
};
use libid_signer::SignerSource;
use tracing::{
    info,
    warn,
};

use crate::{
    chain::{
        self,
        RootsReading,
    },
    config::{
        KeeperConfig,
        ResolvedNetwork,
    },
    decision::{
        self,
        GoogleKey,
    },
    proof::ProofSource,
};

/// What one tick did.
#[derive(Debug, Default)]
pub struct TickOutcome {
    /// Networks whose `IdentityJwksRoots` was read successfully.
    pub networks_read: usize,
    /// Networks that needed a rotation.
    pub rotations_needed: usize,
    /// Rotations submitted and confirmed.
    pub rotations_submitted: usize,
    /// Errors encountered (an erroring network never blocks the others).
    pub errors: usize,
}

impl TickOutcome {
    /// True when everything the tick attempted succeeded.
    pub fn is_success(&self) -> bool {
        self.errors == 0
    }
}

/// Fetch the live JWKS over plain HTTPS — Google's endpoint, unless the
/// mock-notary test seam overrides the URL. The poll and the proof must read
/// the SAME endpoint: otherwise the verdicts are about one key set and the
/// submitted claims attest another.
async fn fetch_google_keys(config: &KeeperConfig) -> Result<Vec<GoogleKey>> {
    let url = config
        .mock_notary
        .as_ref()
        .and_then(|mock| mock.jwks_url.as_deref())
        .unwrap_or(decision::GOOGLE_JWKS_URL);
    let body = reqwest::get(url)
        .await
        .context("fetching Google's JWKS")?
        .error_for_status()
        .context("Google's JWKS endpoint answered an error")?
        .bytes()
        .await
        .context("reading Google's JWKS body")?;
    decision::parse_google_jwks(&body)
}

/// One pass over every network. Decisions come first for ALL networks, so a
/// single notarized reading (obtained at most once per tick) serves every
/// contract that needs it — the record is valid anywhere the notary is
/// trusted, by design.
pub async fn tick(
    config: &KeeperConfig,
    networks: &[ResolvedNetwork],
    dry_run: bool,
) -> TickOutcome {
    let mut outcome = TickOutcome::default();

    let google_keys = match fetch_google_keys(config).await {
        Ok(keys) => keys,
        Err(e) => {
            warn!(error = %e, "tick aborted: could not fetch Google's JWKS");
            outcome.errors += 1;
            return outcome;
        }
    };
    info!(
        kids = ?google_keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
        "polled Google's live JWKS"
    );

    // ── decide ──────────────────────────────────────────────────────────────
    let mut needy: Vec<(&ResolvedNetwork, RootsReading)> = Vec::new();
    for network in networks {
        match read_network(config, network, &google_keys).await {
            Ok(reading) => {
                outcome.networks_read += 1;
                let contract = network.identity_jwks_roots;
                if reading.needs_rotation() {
                    outcome.rotations_needed += 1;
                    for (kid, verdict) in &reading.keys {
                        info!(
                            network = %network.name,
                            contract = %contract,
                            kid = %kid,
                            verdict = verdict.label(),
                            "rotation required"
                        );
                    }
                    needy.push((network, reading));
                } else {
                    info!(
                        network = %network.name,
                        contract = %contract,
                        "up-to-date, no rotation needed"
                    );
                }
            }
            Err(e) => {
                warn!(network = %network.name, error = %e, "network read failed");
                outcome.errors += 1;
            }
        }
    }

    if needy.is_empty() {
        return outcome;
    }
    if dry_run {
        info!(
            networks = needy.len(),
            "dry run: rotations needed but not submitted"
        );
        return outcome;
    }

    // ── notarize once ───────────────────────────────────────────────────────
    let source = match ProofSource::from_config(config) {
        Ok(source) => source,
        Err(e) => {
            warn!(error = %e, "cannot obtain a notarized reading");
            outcome.errors += 1;
            return outcome;
        }
    };
    let session = match source.obtain().await {
        Ok(session) => session,
        Err(e) => {
            warn!(error = %e, "notarized JWKS reading failed");
            outcome.errors += 1;
            return outcome;
        }
    };
    let calldata = chain::rotate_calldata(&session);

    // ── submit ──────────────────────────────────────────────────────────────
    for (network, _) in needy {
        match submit_to(network, calldata.clone()).await {
            Ok(()) => outcome.rotations_submitted += 1,
            Err(e) => {
                warn!(
                    network = %network.name,
                    contract = %network.identity_jwks_roots,
                    error = %e,
                    "rotation submission failed"
                );
                outcome.errors += 1;
            }
        }
    }
    outcome
}

/// Read one network's `IdentityJwksRoots`.
async fn read_network(
    config: &KeeperConfig,
    network: &ResolvedNetwork,
    google_keys: &[GoogleKey],
) -> Result<RootsReading> {
    let provider = ProviderBuilder::new()
        .connect(&network.rpc_url)
        .await
        .with_context(|| format!("connecting to {}", network.rpc_url))?;
    let now = chain::chain_now(&provider).await?;
    chain::read_roots(
        &provider,
        network.identity_jwks_roots,
        google_keys,
        now,
        config.renewal_threshold_secs,
    )
    .await
    .with_context(|| format!("reading {}", network.identity_jwks_roots))
}

/// Submit one rotation with the network's gas signer, which also pays the
/// Notary Fee.
async fn submit_to(network: &ResolvedNetwork, calldata: Vec<u8>) -> Result<()> {
    let spec = network.signer.as_deref().with_context(|| {
        format!(
            "network '{}' needs a rotation but has no gas signer configured",
            network.name
        )
    })?;
    let source = SignerSource::from_spec(spec)
        .map_err(|e| anyhow::anyhow!("gas signer spec: {e}"))?;
    let (wallet, sender) = source
        .build_wallet(None)
        .await
        .map_err(|e| anyhow::anyhow!("gas signer build: {e}"))?;
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&network.rpc_url)
        .await
        .with_context(|| format!("connecting to {}", network.rpc_url))?;
    info!(
        network = %network.name,
        contract = %network.identity_jwks_roots,
        sender = %sender,
        "submitting rotate()"
    );
    let (tx_hash, gas_used) =
        chain::submit_rotation(&provider, network.identity_jwks_roots, calldata).await?;
    info!(
        network = %network.name,
        contract = %network.identity_jwks_roots,
        tx = %tx_hash,
        gas_used,
        "rotate() confirmed"
    );
    Ok(())
}

/// The read-only status table: per network, every live Google kid with its
/// on-chain verdict. Returns an error when any network read fails; a stale
/// chain is NOT an error (that is what the keeper is for).
pub async fn status(config: &KeeperConfig, networks: &[ResolvedNetwork]) -> Result<()> {
    let google_keys = fetch_google_keys(config).await?;
    println!(
        "{:<16} {:<46} {:<12} verdict",
        "network", "kid", "expires-in"
    );
    let mut failures = 0usize;
    for network in networks {
        match read_network(config, network, &google_keys).await {
            Ok(reading) => {
                for (kid, verdict) in &reading.keys {
                    use crate::decision::KeyVerdict;
                    let left = match verdict {
                        KeyVerdict::Fresh { secs_left }
                        | KeyVerdict::Expiring { secs_left } => human_secs(*secs_left),
                        KeyVerdict::Expired => "expired".into(),
                        KeyVerdict::Untrusted => "-".into(),
                    };
                    println!(
                        "{:<16} {:<46} {:<12} {}",
                        network.name,
                        kid,
                        left,
                        verdict.label()
                    );
                }
                println!(
                    "{:<16} {} => {}",
                    network.name,
                    network.identity_jwks_roots,
                    if reading.needs_rotation() {
                        "NEEDS ROTATION"
                    } else {
                        "up-to-date"
                    }
                );
            }
            Err(e) => {
                failures += 1;
                println!("{:<16} read failed: {e:#}", network.name);
            }
        }
    }
    if failures > 0 {
        bail!("{failures} network(s) could not be read");
    }
    Ok(())
}

/// `86400` → `1d0h`, for the status table.
fn human_secs(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    if days > 0 {
        format!("{days}d{hours}h")
    } else {
        let mins = (secs % 3_600) / 60;
        format!("{hours}h{mins}m")
    }
}
