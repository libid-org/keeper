//! The tick: poll → decide → (maybe) notarize → submit. Plus the read-only
//! status table.

use alloy::{
    primitives::Address,
    providers::ProviderBuilder,
};
use anyhow::{
    bail,
    Context,
    Result,
};
use libid_signer::SignerSource;

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
        JwksKey,
        KeyVerdict,
    },
    jwks::Issuer,
    proof::ProofSource,
};

/// What one tick did.
#[derive(Debug, Default)]
pub struct TickOutcome {
    /// Roots contracts read successfully, across issuers and networks.
    pub contracts_read: usize,
    /// Roots contracts that needed a rotation.
    pub rotations_needed: usize,
    /// Rotations submitted and confirmed.
    pub rotations_submitted: usize,
    /// Errors encountered (an erroring issuer or network never blocks the
    /// others).
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

/// Fetch `issuer`'s live JWKS over plain HTTPS. The poll and the proof must
/// read the SAME endpoint, or the verdicts are about one key set and the
/// submitted claims attest another: both fetch [`Issuer::url`], and a test in
/// `jwks` holds the two together. reqwest decompresses what Telegram
/// compresses.
async fn fetch_keys(issuer: Issuer) -> Result<Vec<JwksKey>> {
    let body = reqwest::get(issuer.url())
        .await
        .with_context(|| format!("fetching {}'s JWKS", issuer.name()))?
        .error_for_status()
        .with_context(|| format!("{}'s JWKS endpoint answered an error", issuer.name()))?
        .bytes()
        .await
        .with_context(|| format!("reading {}'s JWKS body", issuer.name()))?;
    decision::parse_jwks(&body).with_context(|| format!("{}'s JWKS", issuer.name()))
}

/// The roots contracts `issuer` has across `networks`.
fn targets(
    networks: &[ResolvedNetwork],
    issuer: Issuer,
) -> Vec<(&ResolvedNetwork, Address)> {
    networks
        .iter()
        .filter_map(|network| network.roots(issuer).map(|roots| (network, roots)))
        .collect()
}

/// One pass over every issuer and network.
pub async fn tick(
    config: &KeeperConfig,
    networks: &[ResolvedNetwork],
    dry_run: bool,
) -> TickOutcome {
    let mut outcome = TickOutcome::default();
    for issuer in Issuer::ALL {
        let targets = targets(networks, issuer);
        if !targets.is_empty() {
            tick_issuer(config, issuer, &targets, dry_run, &mut outcome).await;
        }
    }
    outcome
}

/// One issuer's pass. Decisions come first for ALL its contracts, so a
/// single notarized reading (obtained at most once per tick) serves every
/// contract that needs it — the record is valid anywhere the notary is
/// trusted, by design.
async fn tick_issuer(
    config: &KeeperConfig,
    issuer: Issuer,
    targets: &[(&ResolvedNetwork, Address)],
    dry_run: bool,
    outcome: &mut TickOutcome,
) {
    let live_keys = match fetch_keys(issuer).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(
                issuer = issuer.name(),
                error = format_args!("{e:#}"),
                "issuer skipped: could not fetch its JWKS"
            );
            outcome.errors += 1;
            return;
        }
    };
    tracing::info!(
        issuer = issuer.name(),
        kids = ?live_keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
        "polled the live JWKS"
    );

    // ── decide ──────────────────────────────────────────────────────────────
    let mut needy: Vec<(&ResolvedNetwork, Address)> = Vec::new();
    for &(network, contract) in targets {
        match read_network(config, network, issuer, contract, &live_keys).await {
            Ok(reading) => {
                outcome.contracts_read += 1;
                if reading.needs_rotation() {
                    outcome.rotations_needed += 1;
                    for (kid, verdict) in &reading.keys {
                        tracing::info!(
                            network = %network.name,
                            issuer = issuer.name(),
                            contract = %contract,
                            kid = %kid,
                            verdict = verdict.label(),
                            "rotation required"
                        );
                    }
                    needy.push((network, contract));
                } else {
                    tracing::info!(
                        network = %network.name,
                        issuer = issuer.name(),
                        contract = %contract,
                        "up-to-date, no rotation needed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(network = %network.name, issuer = issuer.name(), error = format_args!("{e:#}"), "network read failed");
                outcome.errors += 1;
            }
        }
    }

    if needy.is_empty() {
        return;
    }
    if dry_run {
        tracing::info!(
            issuer = issuer.name(),
            networks = needy.len(),
            "dry run: rotations needed but not submitted"
        );
        return;
    }

    // ── notarize once ───────────────────────────────────────────────────────
    let source = match ProofSource::from_config(config) {
        Ok(source) => source,
        Err(e) => {
            tracing::warn!(
                error = format_args!("{e:#}"),
                "cannot obtain a notarized reading"
            );
            outcome.errors += 1;
            return;
        }
    };
    let session = match source.obtain(issuer).await {
        Ok(session) => session,
        Err(e) => {
            tracing::warn!(
                issuer = issuer.name(),
                error = format_args!("{e:#}"),
                "notarized JWKS reading failed"
            );
            outcome.errors += 1;
            return;
        }
    };
    let calldata = chain::rotate_calldata(&session);

    // ── submit ──────────────────────────────────────────────────────────────
    for (network, contract) in needy {
        match submit_to(network, contract, calldata.clone()).await {
            Ok(()) => outcome.rotations_submitted += 1,
            Err(e) => {
                tracing::warn!(
                    network = %network.name,
                    contract = %contract,
                    error = format_args!("{e:#}"),
                    "rotation submission failed"
                );
                outcome.errors += 1;
            }
        }
    }
}

/// Read one roots contract on one network.
async fn read_network(
    config: &KeeperConfig,
    network: &ResolvedNetwork,
    issuer: Issuer,
    contract: Address,
    live_keys: &[JwksKey],
) -> Result<RootsReading> {
    let provider = ProviderBuilder::new().connect_client(network.client()?);
    let now = chain::chain_now(&provider).await?;
    chain::read_roots(
        &provider,
        issuer,
        contract,
        live_keys,
        now,
        config.renewal_threshold_secs,
    )
    .await
    .with_context(|| format!("reading {contract}"))
}

/// Submit one rotation with the network's gas signer, which also pays the
/// Notary Fee.
async fn submit_to(
    network: &ResolvedNetwork,
    contract: Address,
    calldata: Vec<u8>,
) -> Result<()> {
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
        .connect_client(network.client()?);
    tracing::info!(
        network = %network.name,
        contract = %contract,
        sender = %sender,
        "submitting rotate()"
    );
    let (tx_hash, gas_used) =
        chain::submit_rotation(&provider, contract, calldata).await?;
    tracing::info!(
        network = %network.name,
        contract = %contract,
        tx = %tx_hash,
        gas_used,
        "rotate() confirmed"
    );
    Ok(())
}

/// The read-only status table: per issuer and network, every live kid with
/// its on-chain verdict. Returns an error when any read fails; a stale chain
/// is NOT an error (that is what the keeper is for).
pub async fn status(config: &KeeperConfig, networks: &[ResolvedNetwork]) -> Result<()> {
    println!(
        "{:<10} {:<16} {:<46} {:<12} verdict",
        "issuer", "network", "kid", "expires-in"
    );
    let mut failures = 0usize;
    for issuer in Issuer::ALL {
        let targets = targets(networks, issuer);
        if targets.is_empty() {
            continue;
        }
        let live_keys = match fetch_keys(issuer).await {
            Ok(keys) => keys,
            Err(e) => {
                failures += 1;
                println!("{:<10} JWKS fetch failed: {e:#}", issuer.name());
                continue;
            }
        };
        for (network, contract) in targets {
            match read_network(config, network, issuer, contract, &live_keys).await {
                Ok(reading) => {
                    for (kid, verdict) in &reading.keys {
                        let left = match verdict {
                            KeyVerdict::Fresh { secs_left }
                            | KeyVerdict::Expiring { secs_left } => {
                                human_secs(*secs_left)
                            }
                            KeyVerdict::Expired => "expired".into(),
                            KeyVerdict::Untrusted => "-".into(),
                        };
                        println!(
                            "{:<10} {:<16} {:<46} {:<12} {}",
                            issuer.name(),
                            network.name,
                            kid,
                            left,
                            verdict.label()
                        );
                    }
                    println!(
                        "{:<10} {:<16} {} => {}",
                        issuer.name(),
                        network.name,
                        contract,
                        if reading.needs_rotation() {
                            "NEEDS ROTATION"
                        } else {
                            "up-to-date"
                        }
                    );
                }
                Err(e) => {
                    failures += 1;
                    println!(
                        "{:<10} {:<16} read failed: {e:#}",
                        issuer.name(),
                        network.name
                    );
                }
            }
        }
    }
    if failures > 0 {
        bail!("{failures} read(s) failed");
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
    use std::time::Duration;

    use super::*;

    /// The API key in [`network`]'s endpoint, which nothing listens on.
    const KEY: &str = "fake-api-key";

    fn network(signer: Option<&str>) -> ResolvedNetwork {
        ResolvedNetwork {
            name: "n".into(),
            rpc_url: format!("http://127.0.0.1:1/v2/{KEY}").parse().unwrap(),
            rpc_timeout: Duration::from_secs(10),
            signer: signer.map(str::to_string),
            google_jwt_roots: Some(Address::ZERO),
            telegram_jwt_roots: None,
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

    #[tokio::test]
    async fn a_failed_read_names_no_endpoint() {
        let error = read_network(
            &config(None),
            &network(None),
            Issuer::Google,
            Address::ZERO,
            &[],
        )
        .await
        .unwrap_err();
        let message = format!("{error:#} {error:?}");
        assert!(message.contains("error sending request"), "{message}");
        assert!(!message.contains(KEY), "{message}");
    }

    #[tokio::test]
    async fn a_failed_submission_names_no_endpoint() {
        let error =
            submit_to(&network(Some(&"ab".repeat(32))), Address::ZERO, Vec::new())
                .await
                .unwrap_err();
        let message = format!("{error:#} {error:?}");
        assert!(message.contains("quoteRotation() failed"), "{message}");
        assert!(message.contains("error sending request"), "{message}");
        assert!(!message.contains(KEY), "{message}");
    }
}
