//! On-chain reads and the rotation submission.
//!
//! The one target is `GoogleJwtRoots`. Trust is by MODULUS:
//! `trustedHashExpiresAt(modulusHash)` is what `GooglePlatformVerifier` reads
//! (the JWT circuit does not expose `kid`), so it is what the keeper reads
//! too. A rotation is `rotate(attestedData, proof)` — the notarized session
//! as the notary handed it over, nothing re-encoded — sent with the Notary
//! Fee attached: the contract forwards `msg.value` whole to the Notary
//! Service, which refuses anything but the exact fee.
//!
//! The contract also exposes `currentRoots()`, `freshestObservedAt()` and
//! `needsRotation()`. `currentRoots()` could collapse the per-key reads below
//! into one call. `needsRotation()` is NOT a substitute for the per-key
//! verdicts: it is contract-side only (it cannot see Google's live set, so a
//! freshly published kid does not trip it while an older key still has
//! runway) and its 7-day runway is fixed where `renewal_threshold_secs` is
//! configurable — so the decision stays here.

use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    primitives::{
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
use libid_contracts::bindings::ceremony::GoogleJwtRoots;
use notary::NotarizedSession;
use tracing::info;

use crate::decision::{
    key_verdict,
    GoogleKey,
    KeyVerdict,
};

/// The verdicts for one `GoogleJwtRoots`, one entry per live Google key.
#[derive(Debug, Clone)]
pub struct RootsReading {
    /// `(kid, verdict)` for every key Google currently publishes.
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

/// Read the trust state of the `GoogleJwtRoots` at `roots` for every live
/// Google key and classify it.
pub async fn read_roots<P: Provider>(
    provider: &P,
    roots: Address,
    google_keys: &[GoogleKey],
    now: u64,
    threshold: u64,
) -> Result<RootsReading> {
    let contract = GoogleJwtRoots::new(roots, provider);
    let mut keys = Vec::with_capacity(google_keys.len());
    for key in google_keys {
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
    GoogleJwtRoots::rotateCall {
        attestedData: Bytes::from(session.attested_data.clone()),
        proof: Bytes::from(session.notary_signature.clone()),
    }
    .abi_encode()
}

/// Submit `rotate(...)` to `roots` with the Notary Fee attached and wait for
/// the receipt. Returns the transaction hash and gas used; errors when the
/// transaction reverts.
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
    let fee = GoogleJwtRoots::new(roots, provider)
        .quoteRotation()
        .call()
        .await
        .context("quoteRotation() failed")?;
    info!(contract = %roots, fee_wei = %fee, "rotate() costs the Notary Fee");
    let tx = TransactionRequest::default()
        .with_to(roots)
        .with_value(fee)
        .with_input(Bytes::from(calldata));
    let receipt = provider
        .send_transaction(tx)
        .await
        .context("rotate() send failed")?
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
    use super::*;

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
        assert_eq!(&calldata[..4], GoogleJwtRoots::rotateCall::SELECTOR);

        let decoded = GoogleJwtRoots::rotateCall::abi_decode(&calldata).unwrap();
        assert_eq!(
            decoded.attestedData.as_ref(),
            session.attested_data.as_slice()
        );
        assert_eq!(decoded.proof.as_ref(), session.notary_signature.as_slice());
    }
}
