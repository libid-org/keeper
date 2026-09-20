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
    /// Networks whose `GoogleJwtRoots` was read successfully.
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

/// Refuse to start a submitting keeper (`run` / `once` without `--dry-run`)
/// on a config that can only fail later. A missing proof source or gas
/// signer surfaces only when a rotation is due, which may be weeks after the
/// deployment went "healthy" — so a deployment learns about it now, at
/// startup, with the same message it would otherwise meet in a warning at
/// 3am. Nothing here touches the network: signer specs are classified by
/// shape, so a KMS id passes without credentials.
pub fn check_can_submit(
    config: &KeeperConfig,
    networks: &[ResolvedNetwork],
) -> Result<()> {
    ProofSource::from_config(config)?;
    for network in networks {
        let spec = network.signer.as_deref().with_context(|| {
            format!(
                "network '{}' has no gas signer — set `signer` at the top level or \
                 on the network entry (or use --dry-run to only report)",
                network.name
            )
        })?;
        SignerSource::from_spec(spec).map_err(|e| {
            anyhow::anyhow!("network '{}' gas signer spec: {e}", network.name)
        })?;
    }
    Ok(())
}

/// Fetch the live JWKS over plain HTTPS from Google's endpoint. The poll and
/// the proof must read the SAME endpoint, or the verdicts are about one key
/// set and the submitted claims attest another: [`decision::GOOGLE_JWKS_URL`]
/// is the URL `jwks::request` targets, and a test there holds the two
/// together.
async fn fetch_google_keys() -> Result<Vec<GoogleKey>> {
    let body = reqwest::get(decision::GOOGLE_JWKS_URL)
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

    let google_keys = match fetch_google_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!(
                error = format_args!("{e:#}"),
                "tick aborted: could not fetch Google's JWKS"
            );
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
                let contract = network.google_jwt_roots;
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
                warn!(network = %network.name, error = format_args!("{e:#}"), "network read failed");
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
            warn!(
                error = format_args!("{e:#}"),
                "cannot obtain a notarized reading"
            );
            outcome.errors += 1;
            return outcome;
        }
    };
    let session = match source.obtain().await {
        Ok(session) => session,
        Err(e) => {
            warn!(
                error = format_args!("{e:#}"),
                "notarized JWKS reading failed"
            );
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
                    contract = %network.google_jwt_roots,
                    error = format_args!("{e:#}"),
                    "rotation submission failed"
                );
                outcome.errors += 1;
            }
        }
    }
    outcome
}

/// Read one network's `GoogleJwtRoots`.
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
        network.google_jwt_roots,
        google_keys,
        now,
        config.renewal_threshold_secs,
    )
    .await
    .with_context(|| format!("reading {}", network.google_jwt_roots))
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
        contract = %network.google_jwt_roots,
        sender = %sender,
        "submitting rotate()"
    );
    let (tx_hash, gas_used) =
        chain::submit_rotation(&provider, network.google_jwt_roots, calldata).await?;
    info!(
        network = %network.name,
        contract = %network.google_jwt_roots,
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
    let google_keys = fetch_google_keys().await?;
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
                    network.google_jwt_roots,
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

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;

    use super::*;

    fn network(signer: Option<&str>) -> ResolvedNetwork {
        ResolvedNetwork {
            name: "n".into(),
            rpc_url: "http://127.0.0.1:1".into(),
            signer: signer.map(str::to_string),
            google_jwt_roots: Address::ZERO,
        }
    }

    fn config(notary_url: Option<&str>) -> KeeperConfig {
        KeeperConfig {
            notary_url: notary_url.map(str::to_string),
            ..toml::from_str("").unwrap()
        }
    }

    #[test]
    fn submitting_needs_a_proof_source() {
        let err = check_can_submit(&config(None), &[network(Some(&"ab".repeat(32)))])
            .unwrap_err();
        assert!(err.to_string().contains("notary_url"), "{err:#}");
    }

    #[test]
    fn submitting_needs_a_gas_signer_on_every_network() {
        let networks = [network(Some(&"ab".repeat(32))), network(None)];
        let err = check_can_submit(&config(Some("tcp://127.0.0.1:7047")), &networks)
            .unwrap_err();
        assert!(err.to_string().contains("no gas signer"), "{err:#}");
    }

    #[test]
    fn a_malformed_signer_spec_is_refused_up_front() {
        let networks = [network(Some("0xabc"))];
        let err = check_can_submit(&config(Some("tcp://127.0.0.1:7047")), &networks)
            .unwrap_err();
        assert!(err.to_string().contains("gas signer spec"), "{err:#}");
    }

    #[test]
    fn a_notary_and_a_signer_per_network_pass() {
        let networks = [
            network(Some(&"ab".repeat(32))),
            network(Some("alias/keeper-gas")),
        ];
        check_can_submit(&config(Some("tcp://127.0.0.1:7047")), &networks).unwrap();
    }
}
