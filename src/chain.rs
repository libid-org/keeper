//! On-chain reads and the rotation submission.
//!
//! The targets are the roots contracts, `GoogleJwtRoots` and
//! `TelegramJwtRoots`. Both are `JwtRootsBase` with one ABI, so the
//! `GoogleJwtRoots` binding serves both. Trust is by MODULUS:
//! `trustedHashExpiresAt(modulusHash)` is what a Platform Verifier reads
//! (the JWT circuit does not expose `kid`), so it is what the keeper reads
//! too. A rotation is `rotate(attestedData, proof)` — the notarized session
//! as the notary handed it over, nothing re-encoded — sent with the Notary
//! Fee attached: the contract forwards `msg.value` whole to the Notary
//! Service, which refuses anything but the exact fee.
//!
//! The contract keeps two generations of the issuer's key set (the latest
//! reading and the one before it) and exposes them as `currentKeys()`, with
//! `freshestObservedAt()` and `needsRotation()` beside them. `needsRotation()`
//! is NOT a substitute for the per-key verdicts: it is contract-side only (it
//! cannot see the issuer's live set, so a freshly published key does not trip it
//! while the current reading still has runway) and its 7-day runway is fixed
//! where `renewal_threshold_secs` is configurable — so the decision stays here.

use std::time::Duration;

use crate::jwks::NotarizedSession;
use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    primitives::{
        keccak256,
        Address,
        Bytes,
        TxHash,
        U256,
    },
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use anyhow::{
    bail,
    Context,
    Result,
};
// `JwtRootsBase`'s ABI, which `TelegramJwtRoots` shares.
use libid_contracts::bindings::ceremony::GoogleJwtRoots as JwtRoots;

use crate::{
    decision::{
        key_verdict,
        KeyVerdict,
        LiveKeys,
    },
    jwks::Issuer,
};

/// The verdicts for one roots contract, one entry per live issuer key.
#[derive(Debug, Clone)]
pub struct RootsReading {
    /// `(kid, verdict)` for every key the issuer currently publishes.
    pub keys: Vec<(String, KeyVerdict)>,
}

impl RootsReading {
    /// True when any key justifies a rotation.
    pub fn needs_rotation(&self) -> bool {
        self.keys.iter().any(|(_, v)| v.needs_rotation())
    }
}

/// The latest block timestamp — the clock the contract compares expiries
/// against, so decisions use it instead of the keeper host's wall clock.
pub async fn chain_now<P: Provider>(provider: &P) -> Result<u64> {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .context("fetching latest block")?
        .context("chain has no latest block")?;
    Ok(block.header.timestamp)
}

/// Read the trust state of `issuer`'s roots contract at `roots` for every
/// live key of the issuer and classify it against the chain's clock. Fails
/// when the contract would refuse any reading of `live`: it pins another host
/// (`WrongAuthority`), or the issuer lists more than its `MAX_KEYS`.
pub async fn read_roots<P: Provider>(
    provider: &P,
    issuer: Issuer,
    roots: Address,
    live: &LiveKeys,
    threshold: u64,
) -> Result<RootsReading> {
    let contract = JwtRoots::new(roots, provider);
    let authority = contract
        .AUTHORITY()
        .call()
        .await
        .context("AUTHORITY() failed")?;
    if authority != keccak256(issuer.host()) {
        bail!(
            "{roots} is not {issuer}'s roots contract: it pins another host than {}",
            issuer.host()
        );
    }
    let max_keys = contract
        .MAX_KEYS()
        .call()
        .await
        .context("MAX_KEYS() failed")?;
    if U256::from(live.entries) > max_keys {
        bail!(
            "{issuer} lists {} keys, more than the {max_keys} {roots} reads (TooManyKeys)",
            live.entries
        );
    }
    let now = chain_now(provider).await?;
    let mut keys = Vec::with_capacity(live.keys.len());
    for key in &live.keys {
        let expiry = contract
            .trustedHashExpiresAt(key.modulus_hash)
            .call()
            .await
            .with_context(|| format!("trustedHashExpiresAt({}) failed", key.kid))?;
        keys.push((
            key.kid.clone(),
            key_verdict(to_expiry(expiry), now, threshold),
        ));
    }
    Ok(RootsReading { keys })
}

/// Collapse a U256 expiry to the `Option<u64>` the verdict works over. Zero
/// is the contract's "not trusted" sentinel; anything beyond u64 is treated
/// as far-future.
fn to_expiry(expiry: U256) -> Option<u64> {
    if expiry.is_zero() {
        None
    } else {
        Some(expiry.try_into().unwrap_or(u64::MAX))
    }
}

/// ABI-encode `rotate(attestedData, proof)` from a notarized session. The
/// record goes in as the notary encoded it: the signature is over exactly
/// those bytes, and the contract derives the notary key from the pair alone.
pub fn rotate_calldata(session: &NotarizedSession) -> Vec<u8> {
    JwtRoots::rotateCall {
        attestedData: Bytes::from(session.attested_data.clone()),
        proof: Bytes::from(session.notary_signature.clone()),
    }
    .abi_encode()
}

/// How long [`submit_rotation`] waits for the receipt. A rotation that lands
/// later is read as trusted on the next tick.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Submit `rotate(...)` to `roots` with the Notary Fee attached and wait for
/// the receipt, up to [`RECEIPT_TIMEOUT`]. Returns the transaction hash and
/// gas used; errors when the transaction reverts.
///
/// The fee is quoted right before sending, not at read time: `rotate` takes
/// exactly `quoteRotation()` (the Notary Service's current `fee()`), so a fee
/// change between the decision and the submission would otherwise revert
/// with `WrongValue` after the MPC-TLS session was already paid for.
pub async fn submit_rotation<P: Provider>(
    provider: &P,
    roots: Address,
    calldata: Vec<u8>,
) -> Result<(TxHash, u64)> {
    let fee = JwtRoots::new(roots, provider)
        .quoteRotation()
        .call()
        .await
        .context("quoteRotation() failed")?;
    tracing::info!(contract = %roots, fee_wei = %fee, "rotate() costs the Notary Fee");
    let tx = TransactionRequest::default()
        .with_to(roots)
        .with_value(fee)
        .with_input(Bytes::from(calldata));
    let receipt = provider
        .send_transaction(tx)
        .await
        .context("rotate() send failed")?
        .with_timeout(Some(RECEIPT_TIMEOUT))
        .get_receipt()
        .await
        .context("rotate() receipt failed")?;
    if !receipt.status() {
        bail!(
            "rotate() reverted on chain (tx {})",
            receipt.transaction_hash
        );
    }
    Ok((receipt.transaction_hash, receipt.gas_used))
}

#[cfg(test)]
mod tests {
    use alloy::{
        providers::ProviderBuilder,
        sol_types::SolValue,
        transports::mock::Asserter,
    };

    use super::*;
    use crate::decision::JwksKey;

    /// A provider answering `eth_call`s from `answers`, in order.
    fn mocked(answers: &[Vec<u8>]) -> impl Provider {
        let asserter = Asserter::new();
        for answer in answers {
            asserter.push_success(&Bytes::from(answer.clone()));
        }
        ProviderBuilder::new().connect_mocked_client(asserter)
    }

    fn live(entries: usize) -> LiveKeys {
        LiveKeys {
            keys: vec![JwksKey {
                kid: "k".into(),
                modulus_hash: Default::default(),
            }],
            entries,
        }
    }

    #[tokio::test]
    async fn a_contract_pinning_another_host_is_refused() {
        let provider = mocked(&[keccak256("www.googleapis.com").abi_encode()]);
        let err = read_roots(&provider, Issuer::Telegram, Address::ZERO, &live(1), 0)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("pins another host than oauth.telegram.org"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn more_entries_than_max_keys_are_refused() {
        let provider = mocked(&[
            keccak256("oauth.telegram.org").abi_encode(),
            U256::from(4).abi_encode(),
        ]);
        let err = read_roots(&provider, Issuer::Telegram, Address::ZERO, &live(5), 0)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("TooManyKeys"), "{err:#}");
    }

    /// Both halves of the record land in the corresponding ABI slot,
    /// untouched: decode the encoded calldata back and compare. This is the
    /// seam between the notary's wire format and the `rotate(bytes,bytes)`
    /// ABI — the signature is over `attested_data`, so a byte moved here is
    /// a rotation the Notary Service refuses.
    #[test]
    fn rotate_calldata_round_trips_through_the_abi() {
        let session = NotarizedSession {
            attested_data: (0..=255u8).cycle().take(700).collect(),
            notary_signature: vec![0xab; 65],
        };

        let calldata = rotate_calldata(&session);
        assert_eq!(&calldata[..4], JwtRoots::rotateCall::SELECTOR);

        let decoded = JwtRoots::rotateCall::abi_decode(&calldata).unwrap();
        assert_eq!(
            decoded.attestedData.as_ref(),
            session.attested_data.as_slice()
        );
        assert_eq!(decoded.proof.as_ref(), session.notary_signature.as_slice());
    }
}
